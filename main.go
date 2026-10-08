package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
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

	// Health check sederhana
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","app":"lemes-honeybeacon","version":"%s","time":"%s"}`, appVersion, time.Now().Format(time.RFC3339))
	})

	// Beacon / Tracking Pixel Endpoints
	http.HandleFunc("/beacon", handleBeacon)
	http.HandleFunc("/beacon/pixel.png", handleBeacon)
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

	log.Printf("==================================================")
	log.Printf("🍯 Lemes Honeybeacon v%s berjalan di %s", appVersion, *port)
	log.Printf("📌 Sensor ID   : %s", *sensorID)
	log.Printf("📁 CTI Log     : %s", *ctiLog)
	if *cacheDB != "" {
		log.Printf("⚡ cacheDB     : %s", *cacheDB)
	}
	log.Printf("🔗 Generator   : %s/lure", *publicURL)
	log.Printf("🌐 Decoy Portal: %s/", *publicURL)
	log.Printf("🎯 Beacon Pixel: %s/beacon/pixel.png", *publicURL)
	log.Printf("==================================================")

	if err := http.ListenAndServe(*port, nil); err != nil {
		log.Fatalf("Server berhenti dengan error: %v", err)
	}
}
