package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	port      = flag.String("port", ":8080", "Port listener HTTP honeybeacon (contoh: :8080 atau :80)")
	ctiLog    = flag.String("ctilog", "lemes_cti.jsonl", "Path file log CTI (format JSON Lines)")
	sensorID  = flag.String("sensor-id", "", "ID sensor Honeybeacon (default: hostname)")
	cacheDB   = flag.String("cachedb", "", "Alamat gRPC cachedb opsional (contoh: 127.0.0.1:50051)")
	publicURL = flag.String("public-url", "", "URL publik server lemes untuk penyisipan lure beacon (contoh: http://192.168.1.100:8080)")
	versionFlag = flag.Bool("version", false, "Tampilkan versi aplikasi")
)

var appVersion = "0.1.0"

func initConfig() {
	flag.Parse()

	if *versionFlag {
		fmt.Printf("lemes (honeybeacon) v%s\n", appVersion)
		os.Exit(0)
	}

	if *sensorID == "" {
		host, err := os.Hostname()
		if err != nil || host == "" {
			*sensorID = "lemes-honeybeacon"
		} else {
			*sensorID = host
		}
	}

	if *publicURL == "" {
		*publicURL = fmt.Sprintf("http://localhost%s", *port)
	}
}
