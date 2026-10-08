package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/n0z0/cachedb/cdc"
	"github.com/n0z0/cachedb/proto/cachepb"
	"google.golang.org/grpc"
)

// LemesCTIEvent menyimpan data telemetri threat intelligence dari Honeybeacon
type LemesCTIEvent struct {
	Timestamp      string            `json:"timestamp"` // ISO 8601 UTC
	SensorID       string            `json:"sensor_id"`
	EventType      string            `json:"event_type"` // BEACON_TRIGGERED, DECOY_LOGIN_ATTEMPT, DECOY_PROBE_REQUEST
	ClientIP       string            `json:"client_ip"`
	ClientPort     int               `json:"client_port,omitempty"`
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

	logger := &CTILogger{file: f}

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

	ctiLogger = logger
	return ctiLogger, nil
}

func (l *CTILogger) Close() {
	if l != nil {
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
	}

	log.Printf("[CTI ALERT] [%s] %s dari IP %s (UA: %s)", event.EventType, event.Mitre.ID, event.ClientIP, event.UserAgent)
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
