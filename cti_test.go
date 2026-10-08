package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLemesCTIEnrichmentAndWebhook(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test_lemes_cti.jsonl")

	// Setup mock webhook receiver
	var webhookHits int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	globalWebhookCfg = WebhookConfig{
		URL:         mockServer.URL,
		WebhookType: "generic",
	}

	logger, err := initCTILogger(logFile, "")
	if err != nil {
		t.Fatalf("initCTILogger failed: %v", err)
	}
	defer logger.Close()

	// Simulasi event beacon triggered
	event := &LemesCTIEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		SensorID:  "test-lemes",
		EventType: "BEACON_TRIGGERED",
		ClientIP:  "198.51.100.77",
		UserAgent: "Microsoft Office Word",
		TokenID:   "canary_token_01",
		LureFile:  "confidential.docx",
		Mitre: MitreAttackInfo{
			Tactic:    "Execution",
			Technique: "User Execution",
			ID:        "T1204.002",
		},
	}

	logger.asyncEnrichAndLog(event)

	// Biarkan Goroutine memproses
	time.Sleep(300 * time.Millisecond)

	// Cek Webhook berhasil dipanggil
	if atomic.LoadInt32(&webhookHits) == 0 {
		t.Errorf("Expected webhook to be triggered by goroutine")
	}

	// Cek file log
	f, err := os.Open(logFile)
	if err != nil {
		t.Fatalf("Failed to open log file: %v", err)
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("Expected log entry in JSONL")
	}

	var recorded LemesCTIEvent
	if err := json.Unmarshal([]byte(lines[0]), &recorded); err != nil {
		t.Fatalf("Unmarshal log entry failed: %v", err)
	}

	if recorded.ThreatScore < 70 {
		t.Errorf("Expected high threat score, got %d", recorded.ThreatScore)
	}
	if recorded.SessionID == "" {
		t.Errorf("Expected SessionID to be generated")
	}
}

func TestLemesAttributionDeAnonymization(t *testing.T) {
	evt := &LemesCTIEvent{
		EventType:    "BEACON_DEANONYMIZED",
		ClientIP:     "203.0.113.88",
		ScannerIP:    "198.51.100.12",
		Deanonymized: true,
	}

	evaluateThreatScore(evt)

	if evt.ThreatScore != 100 {
		t.Errorf("Expected ThreatScore 100 for de-anonymized event, got %d", evt.ThreatScore)
	}
	if evt.Severity != "CRITICAL" {
		t.Errorf("Expected CRITICAL severity, got %s", evt.Severity)
	}
}
