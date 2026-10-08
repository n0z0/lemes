package main

import (
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
