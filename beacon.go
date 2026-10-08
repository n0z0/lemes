package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// 1x1 transparent PNG byte stream (67 bytes)
var transparentPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
	0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
	0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
}

func handleBeacon(w http.ResponseWriter, r *http.Request) {
	clientIP, clientPort := extractClientIP(r)

	tokenID := r.URL.Query().Get("token")
	if tokenID == "" {
		tokenID = r.URL.Query().Get("id")
	}

	// Dukung path format: /b/<token>
	if tokenID == "" && strings.HasPrefix(r.URL.Path, "/b/") {
		tokenID = strings.TrimPrefix(r.URL.Path, "/b/")
	}

	lureFile := r.URL.Query().Get("file")
	if lureFile == "" {
		lureFile = r.URL.Query().Get("lure")
	}

	event := &LemesCTIEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		SensorID:       *sensorID,
		EventType:      "BEACON_TRIGGERED",
		ClientIP:       clientIP,
		ClientPort:     clientPort,
		UserAgent:      r.UserAgent(),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		Referer:        r.Referer(),
		Method:         r.Method,
		URLPath:        r.URL.Path,
		TokenID:        tokenID,
		LureFile:       lureFile,
		Headers:        extractKeyHeaders(r),
		Mitre: MitreAttackInfo{
			Tactic:    "Execution",
			Technique: "User Execution: Malicious File / Lure Opened",
			ID:        "T1204.002",
		},
	}

	if ctiLogger != nil {
		ctiLogger.LogEvent(event)
	}

	// Kirim balik transparent PNG dan cegah caching browser/proxy
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	w.Write(transparentPNG)
}

func handleTelemetry(w http.ResponseWriter, r *http.Request) {
	// Header CORS agar permintaan fetch dari file:// atau domain lain tidak diblokir browser
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP, clientPort := extractClientIP(r)

	var payload struct {
		TokenID        string   `json:"token_id"`
		LureFile       string   `json:"lure_file"`
		Timezone       string   `json:"timezone"`
		ScreenRes      string   `json:"screen_resolution"`
		ColorDepth     int      `json:"color_depth"`
		CPUCores       int      `json:"cpu_cores"`
		DeviceMemoryGB float64  `json:"device_memory_gb"`
		GPURenderer    string   `json:"gpu_renderer"`
		GPUVendor      string   `json:"gpu_vendor"`
		Languages      []string `json:"languages"`
		Platform       string   `json:"platform"`
		TouchSupport   bool     `json:"touch_support"`
		LocalTime      string   `json:"local_time"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid telemetry JSON", http.StatusBadRequest)
		return
	}

	tokenID := payload.TokenID
	if tokenID == "" {
		tokenID = r.URL.Query().Get("token")
	}
	lureFile := payload.LureFile
	if lureFile == "" {
		lureFile = r.URL.Query().Get("file")
	}

	event := &LemesCTIEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		SensorID:       *sensorID,
		EventType:      "BEACON_TELEMETRY_FINGERPRINT",
		ClientIP:       clientIP,
		ClientPort:     clientPort,
		UserAgent:      r.UserAgent(),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		Referer:        r.Referer(),
		Method:         r.Method,
		URLPath:        r.URL.Path,
		TokenID:        tokenID,
		LureFile:       lureFile,
		Headers:        extractKeyHeaders(r),
		Telemetry: &ClientTelemetry{
			Timezone:       payload.Timezone,
			ScreenRes:      payload.ScreenRes,
			ColorDepth:     payload.ColorDepth,
			CPUCores:       payload.CPUCores,
			DeviceMemoryGB: payload.DeviceMemoryGB,
			GPURenderer:    payload.GPURenderer,
			GPUVendor:      payload.GPUVendor,
			Languages:      payload.Languages,
			Platform:       payload.Platform,
			TouchSupport:   payload.TouchSupport,
			LocalTime:      payload.LocalTime,
		},
		Mitre: MitreAttackInfo{
			Tactic:    "Discovery",
			Technique: "System Information Discovery: Hardware & Environment",
			ID:        "T1082",
		},
	}

	if ctiLogger != nil {
		ctiLogger.LogEvent(event)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"acknowledged"}`))
}

