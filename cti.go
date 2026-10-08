package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n0z0/cachedb/cdc"
	"github.com/n0z0/cachedb/proto/cachepb"
	"google.golang.org/grpc"
)

// ReconProfileInfo menyimpan metadata jejak pengintaian L4 (dari synwatcher via cachedb)
type ReconProfileInfo struct {
	SYNFingerprintHash string `json:"syn_hash,omitempty"`
	RiskScore          string `json:"risk_score,omitempty"`
	Severity           string `json:"severity,omitempty"`
	TargetService      string `json:"target_service,omitempty"`
	IntentCategory     string `json:"intent_category,omitempty"`
	ScanVelocity       string `json:"scan_velocity,omitempty"`
	EstimatedOS        string `json:"estimated_os,omitempty"`
	ScannerTool        string `json:"scanner_tool,omitempty"`
	ScanHits           string `json:"scan_hits,omitempty"`
	LastScan           string `json:"last_scan,omitempty"`
}

// LemesCTIEvent menyimpan data telemetri threat intelligence dari Honeybeacon
type LemesCTIEvent struct {
	Timestamp      string            `json:"timestamp"` // ISO 8601 UTC
	SensorID       string            `json:"sensor_id"`
	SessionID      string            `json:"session_id,omitempty"` // Correlation ID
	EventType      string            `json:"event_type"`           // BEACON_TRIGGERED, DECOY_LOGIN_ATTEMPT, DECOY_PROBE_REQUEST, BEACON_DEANONYMIZED
	Status         string            `json:"status,omitempty"`     // triggered, captured, unmasked
	ThreatScore    int               `json:"threat_score,omitempty"`
	Severity       string            `json:"severity,omitempty"`        // INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
	KillChainPhase string            `json:"kill_chain_phase,omitempty"` // User Execution, Exfiltration, Credential Access, Initial Access
	ClientIP       string            `json:"client_ip"`
	ClientPort     int               `json:"client_port,omitempty"`
	ReverseDNS     string            `json:"reverse_dns,omitempty"` // Hostname hasil PTR lookup via Goroutine
	Deanonymized   bool              `json:"deanonymized,omitempty"`
	ScannerIP      string            `json:"scanner_ip,omitempty"` // IP Scanner L4 yang sebelumnya mengunduh/memicu token
	UserAgent      string            `json:"user_agent"`
	AcceptLanguage string            `json:"accept_language,omitempty"`
	Referer        string            `json:"referer,omitempty"`
	Method         string            `json:"method"`
	URLPath        string            `json:"url_path"`
	TokenID        string            `json:"token_id,omitempty"`
	LureFile       string            `json:"lure_file,omitempty"`
	Credentials    *DecoyCredentials `json:"credentials,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Telemetry      *ClientTelemetry  `json:"telemetry,omitempty"`
	ReconProfile   *ReconProfileInfo `json:"recon_profile,omitempty"`
	Mitre          MitreAttackInfo   `json:"mitre_attack"`
}

type ClientTelemetry struct {
	Timezone       string   `json:"timezone,omitempty"`
	ScreenRes      string   `json:"screen_resolution,omitempty"`
	ColorDepth     int      `json:"color_depth,omitempty"`
	CPUCores       int      `json:"cpu_cores,omitempty"`
	DeviceMemoryGB float64  `json:"device_memory_gb,omitempty"`
	GPURenderer    string   `json:"gpu_renderer,omitempty"`
	GPUVendor      string   `json:"gpu_vendor,omitempty"`
	Languages      []string `json:"languages,omitempty"`
	Platform       string   `json:"platform,omitempty"`
	TouchSupport   bool     `json:"touch_support,omitempty"`
	LocalTime      string   `json:"local_time,omitempty"`
}

type DecoyCredentials struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

type MitreAttackInfo struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	ID        string `json:"technique_id"`
}

type CTILogger struct {
	file        *os.File
	mu          sync.Mutex
	cacheClient cachepb.CacheClient
	grpcConn    *grpc.ClientConn
	eventChan   chan *LemesCTIEvent
	quit        chan struct{}
	wg          sync.WaitGroup
}

var ctiLogger *CTILogger

func initCTILogger(path string, cacheDBAddr string) (*CTILogger, error) {
	var f *os.File
	if path != "" {
		var err error
		f, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("gagal membuka log CTI %s: %w", path, err)
		}
	}

	logger := &CTILogger{
		file:      f,
		eventChan: make(chan *LemesCTIEvent, 4096),
		quit:      make(chan struct{}),
	}

	if cacheDBAddr != "" {
		client, conn, err := cdc.Connect(cacheDBAddr)
		if err != nil {
			log.Printf("[CTI] Peringatan: Tidak dapat terhubung ke cacheDB di %s: %v", cacheDBAddr, err)
		} else {
			logger.cacheClient = client
			logger.grpcConn = conn
			log.Printf("[CTI] Terhubung ke cacheDB di %s", cacheDBAddr)
		}
	}

	// Worker goroutine untuk proses penulisan file dan push ke CacheDB secara non-blocking
	logger.wg.Add(1)
	go func() {
		defer logger.wg.Done()
		for {
			select {
			case event, ok := <-logger.eventChan:
				if !ok {
					return
				}
				logger.processEvent(event)
			case <-logger.quit:
				// Drain event tersisa
				for {
					select {
					case event := <-logger.eventChan:
						logger.processEvent(event)
					default:
						return
					}
				}
			}
		}
	}()

	ctiLogger = logger
	return ctiLogger, nil
}

// resolveReverseDNS melakukan DNS PTR lookup secara non-blocking via Goroutine
func resolveReverseDNS(ipStr string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	var r net.Resolver
	names, err := r.LookupAddr(ctx, ipStr)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ""
}

// generateSessionID membuat correlation ID konsisten berdasarkan IP dan tanggal UTC
func generateSessionID(ip string) string {
	h := sha256.New()
	h.Write([]byte(ip + ":" + time.Now().UTC().Format("2006-01-02")))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// evaluateThreatScore menghitung tingkat keparahan event di lemes
func evaluateThreatScore(evt *LemesCTIEvent) {
	if evt.ThreatScore == 0 {
		switch evt.EventType {
		case "BEACON_DEANONYMIZED":
			evt.ThreatScore = 100
			evt.Severity = "CRITICAL"
			evt.KillChainPhase = "Exfiltration"
		case "BEACON_TRIGGERED":
			evt.ThreatScore = 85
			evt.Severity = "HIGH"
			evt.KillChainPhase = "User Execution"
		case "DECOY_LOGIN_ATTEMPT":
			evt.ThreatScore = 75
			evt.Severity = "HIGH"
			evt.KillChainPhase = "Credential Access"
		case "DECOY_PROBE_REQUEST":
			evt.ThreatScore = 55
			evt.Severity = "MEDIUM"
			evt.KillChainPhase = "Discovery"
		default:
			evt.ThreatScore = 40
			evt.Severity = "LOW"
			evt.KillChainPhase = "Reconnaissance"
		}
	}

	if evt.Deanonymized {
		evt.ThreatScore = 100
		evt.Severity = "CRITICAL"
		evt.KillChainPhase = "Exfiltration"
	}

	if evt.Severity == "" {
		if evt.ThreatScore >= 90 {
			evt.Severity = "CRITICAL"
		} else if evt.ThreatScore >= 70 {
			evt.Severity = "HIGH"
		} else if evt.ThreatScore >= 40 {
			evt.Severity = "MEDIUM"
		} else {
			evt.Severity = "LOW"
		}
	}
}

// asyncEnrichAndLog melakukan korelasi intelijen dan memicu Webhook menggunakan Goroutine
func (l *CTILogger) asyncEnrichAndLog(event *LemesCTIEvent) {
	if l == nil || event == nil {
		return
	}

	// Goroutine terisolasi: zero latency impact ke response HTTP
	go func(evt *LemesCTIEvent) {
		if evt.SessionID == "" && evt.ClientIP != "" {
			evt.SessionID = generateSessionID(evt.ClientIP)
		}

		// Asynchronous Reverse DNS lookup
		if evt.ClientIP != "" && evt.ClientIP != "127.0.0.1" && evt.ClientIP != "::1" && evt.ReverseDNS == "" {
			evt.ReverseDNS = resolveReverseDNS(evt.ClientIP)
		}

		// Korelasi silang ke cacheDB
		if l.cacheClient != nil && evt.ClientIP != "" {
			// 1. Ambil L4 Recon Profile jika ada
			if dossier, found, err := cdc.GetActor(evt.ClientIP, l.cacheClient); err == nil && found && dossier != nil {
				evt.ReconProfile = &ReconProfileInfo{
					SYNFingerprintHash: dossier.SynHash,
					RiskScore:          dossier.RiskScore,
					Severity:           dossier.Severity,
					TargetService:      dossier.TargetService,
					IntentCategory:     dossier.IntentCategory,
					ScanVelocity:       dossier.ScanVelocity,
					EstimatedOS:        dossier.EstimatedOs,
					ScannerTool:        dossier.ScannerTool,
					ScanHits:           dossier.ScanHits,
					LastScan:           dossier.LastActivity,
				}
			}

			// 2. Korelasi De-Anonymization: Cek apakah token atau nama file ini terikat ke IP scanner/downloader lain
			var scannerIP string
			if evt.TokenID != "" {
				scannerIP, _ = cdc.Get("token:owner:"+evt.TokenID, l.cacheClient)
			}
			if scannerIP == "" && evt.LureFile != "" {
				baseName := filepath.Base(evt.LureFile)
				scannerIP, _ = cdc.Get("token:download:"+baseName, l.cacheClient)
				if scannerIP == "" {
					scannerIP, _ = cdc.Get("token:owner:"+baseName, l.cacheClient)
				}
			}

			if scannerIP != "" && scannerIP != evt.ClientIP {
				// Attacker membuka file di IP berbeda (De-anonymization Goldmine!)
				evt.Deanonymized = true
				evt.ScannerIP = scannerIP
				evt.EventType = "BEACON_DEANONYMIZED"
				log.Printf("[SOC ATTRIBUTION] 🎯 ATTACKER UNMASKED! Dokumen curian oleh scanner %s dibuka dari Workstation Asli IP: %s (UA: %s)",
					scannerIP, evt.ClientIP, evt.UserAgent)

				// Update temuan de-anonymization ke cacheDB
				_ = cdc.Set("actor:real_ip:"+scannerIP, evt.ClientIP, l.cacheClient)
				_ = cdc.Set("actor:deanonymized:"+evt.ClientIP, scannerIP, l.cacheClient)
				_ = cdc.Set("actor:risk:"+evt.ClientIP, "100", l.cacheClient)
				_ = cdc.Set("actor:severity:"+evt.ClientIP, "CRITICAL", l.cacheClient)
				_ = cdc.Set("actor:intent:"+evt.ClientIP, "DATA_EXFILTRATION_OPENED", l.cacheClient)
			}
		}

		evaluateThreatScore(evt)

		// Forward ke Webhook Dispatcher (Discord, Telegram, Slack, SIEM) secara asinkron
		DispatchWebhook(evt, globalWebhookCfg)

		// Kirim ke log queue
		l.LogEvent(evt)
	}(event)
}

func (l *CTILogger) processEvent(event *LemesCTIEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[CTI] Gagal serialize JSON event: %v", err)
		return
	}

	// Tulis ke file log JSONL
	if l.file != nil {
		l.mu.Lock()
		l.file.Write(append(data, '\n'))
		l.mu.Unlock()
	}

	// Push ke cacheDB jika terhubung
	if l.cacheClient != nil {
		key := fmt.Sprintf("beacon:%s", event.ClientIP)
		if event.TokenID != "" {
			key = fmt.Sprintf("token:%s", event.TokenID)
		}
		_ = cdc.Set(key, string(data), l.cacheClient)

		if event.ReverseDNS != "" {
			_ = cdc.Set("actor:rdns:"+event.ClientIP, event.ReverseDNS, l.cacheClient)
		}
		if event.Credentials != nil && event.Credentials.Username != "" {
			_ = cdc.Set("actor:lemes:user:"+event.ClientIP, event.Credentials.Username, l.cacheClient)
			_ = cdc.Set("actor:lemes:pass:"+event.ClientIP, event.Credentials.Password, l.cacheClient)
		}
		if event.Telemetry != nil && event.Telemetry.GPURenderer != "" {
			_ = cdc.Set("actor:gpu:"+event.ClientIP, event.Telemetry.GPURenderer, l.cacheClient)
		}
	}

	log.Printf("[CTI ALERT] [%s] %s dari IP %s (Score: %d [%s], UA: %s)",
		event.EventType, event.Mitre.ID, event.ClientIP, event.ThreatScore, event.Severity, event.UserAgent)
}

func (l *CTILogger) Close() {
	if l != nil {
		close(l.quit)
		l.wg.Wait()
		if l.file != nil {
			l.file.Close()
		}
		if l.grpcConn != nil {
			l.grpcConn.Close()
		}
	}
}

func (l *CTILogger) LogEvent(event *LemesCTIEvent) {
	if l == nil {
		return
	}
	select {
	case l.eventChan <- event:
	default:
		go l.processEvent(event)
	}
}

// extractClientIP mengambil IP asli klien dari header reverse proxy atau RemoteAddr
func extractClientIP(r *http.Request) (string, int) {
	// Cek header Cloudflare / reverse proxy
	ipStr := r.Header.Get("CF-Connecting-IP")
	if ipStr == "" {
		ipStr = r.Header.Get("X-Real-IP")
	}
	if ipStr == "" {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			ipStr = strings.TrimSpace(parts[0])
		}
	}

	var port int
	remoteHost, remotePortStr, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		p, _ := strconv.Atoi(remotePortStr)
		port = p
		if ipStr == "" {
			ipStr = remoteHost
		}
	} else if ipStr == "" {
		ipStr = r.RemoteAddr
	}

	return ipStr, port
}

// extractKeyHeaders mengumpulkan header forensik penting
func extractKeyHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)
	checkList := []string{
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Platform-Version",
		"Sec-Fetch-Dest",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Site",
		"Origin",
		"Host",
		"Upgrade-Insecure-Requests",
	}

	for _, h := range checkList {
		val := r.Header.Get(h)
		if val != "" {
			headers[h] = val
		}
	}
	return headers
}
