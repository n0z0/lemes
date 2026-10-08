package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	initConfig()

	// Inisialisasi CTI Logger & CacheDB Client
	logger, err := initCTILogger(*ctiLog, *cacheDB)
	if err != nil {
		log.Fatalf("Gagal inisialisasi logger CTI: %v", err)
	}
	defer logger.Close()

	var tunnelMgr *TunnelManager
	if *tunnelFlag {
		tm, err := startCloudflareTunnel(*port)
		if err != nil {
			log.Fatalf("[TUNNEL ERROR] %v", err)
		}
		tunnelMgr = tm
		*publicURL = tm.PublicURL
		defer tunnelMgr.Stop()
	}

	// Health check sederhana
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","app":"lemes-honeybeacon","version":"%s","time":"%s"}`, appVersion, time.Now().Format(time.RFC3339))
	})

	// Beacon / Tracking Pixel Endpoints
	http.HandleFunc("/beacon", handleBeacon)
	http.HandleFunc("/beacon/pixel.png", handleBeacon)
	http.HandleFunc("/beacon/telemetry", handleTelemetry)
	http.HandleFunc("/track.png", handleBeacon)
	http.HandleFunc("/b/", handleBeacon)

	// Decoy Login Portal & Credential Traps
	http.HandleFunc("/login", handleDecoyPortal)
	http.HandleFunc("/portal", handleDecoyPortal)
	http.HandleFunc("/admin", handleDecoyPortal)

	// Decoy API Traps
	http.HandleFunc("/api/", handleDecoyAPI)

	// Lure Generator & Downloads
	http.HandleFunc("/lure", handleLureDashboard)
	http.HandleFunc("/lure/download/html", handleDownloadLureHTML)

	// Root Handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			handleDecoyPortal(w, r)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/b/") {
			handleBeacon(w, r)
			return
		}

		// Anggap path tak dikenal sebagai probe / reconnaissance
		handleDecoyAPI(w, r)
	})

	server := &http.Server{
		Addr: *port,
	}

	// Tangani sinyal shutdown (Ctrl+C / SIGTERM)
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopChan
		log.Printf("\n[SHUTDOWN] Menghentikan server lemes...")
		if tunnelMgr != nil {
			tunnelMgr.Stop()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("==================================================")
	log.Printf("🍯 Lemes Honeybeacon v%s berjalan di port %s", appVersion, *port)
	log.Printf("📌 Sensor ID   : %s", *sensorID)
	log.Printf("📁 CTI Log     : %s", *ctiLog)
	if *cacheDB != "" {
		log.Printf("⚡ cacheDB     : %s", *cacheDB)
	}
	if *tunnelFlag {
		log.Printf("🌐 HTTPS Tunnel: %s (Cloudflare)", *publicURL)
	}
	log.Printf("🔗 Generator   : %s/lure", *publicURL)
	log.Printf("🌐 Decoy Portal: %s/", *publicURL)
	log.Printf("🎯 Beacon Pixel: %s/beacon/pixel.png", *publicURL)
	log.Printf("==================================================")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server berhenti dengan error: %v", err)
	}
}
