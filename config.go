package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

var (
	port           = flag.String("port", ":50505", "Port listener HTTP honeybeacon (default: :50505)")
	tunnelFlag     = flag.Bool("tunnel", false, "Otomatis jalankan Cloudflare Tunnel (cloudflared) untuk mendapatkan domain HTTPS publik gratis")
	ctiLog         = flag.String("ctilog", "lemes_cti.jsonl", "Path file log CTI (format JSON Lines)")
	sensorID       = flag.String("sensor-id", "", "ID sensor Honeybeacon (default: hostname)")
	cacheDB        = flag.String("cachedb", "127.0.0.1:50051", "Alamat gRPC cachedb (default: 127.0.0.1:50051)")
	publicURL      = flag.String("public-url", "", "URL publik server lemes untuk penyisipan lure beacon (contoh: https://honey.domain.com atau http://192.168.1.100:50505)")
	webhookURL     = flag.String("webhook-url", "", "URL Webhook alerting SOC opsional (Discord, Telegram, Slack, Generic SIEM)")
	webhookType    = flag.String("webhook-type", "generic", "Tipe webhook: discord, telegram, slack, generic")
	telegramChatID = flag.String("telegram-chat-id", "", "Telegram Chat ID (wajib jika webhook-type adalah telegram)")
	versionFlag    = flag.Bool("version", false, "Tampilkan versi aplikasi")
)

var (
	appVersion = "0.1.0"
	localIP    = "127.0.0.1"
)

// detectLocalIP mencari IP LAN non-loopback komputer saat ini
func detectLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		if !localAddr.IP.IsLoopback() {
			return localAddr.IP.String()
		}
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					return ip4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

func initConfig() {
	flag.Parse()

	if *versionFlag {
		fmt.Printf("lemes (honeybeacon) v%s\n", appVersion)
		os.Exit(0)
	}

	if !strings.HasPrefix(*port, ":") {
		*port = ":" + *port
	}

	localIP = detectLocalIP()

	if *sensorID == "" {
		host, err := os.Hostname()
		if err != nil || host == "" {
			*sensorID = "lemes-honeybeacon"
		} else {
			*sensorID = host
		}
	}

	if *publicURL == "" && !*tunnelFlag {
		if localIP != "" && localIP != "127.0.0.1" {
			*publicURL = fmt.Sprintf("http://%s%s", localIP, *port)
		} else {
			*publicURL = fmt.Sprintf("http://localhost%s", *port)
		}
	}

	globalWebhookCfg = WebhookConfig{
		URL:            *webhookURL,
		WebhookType:    *webhookType,
		TelegramChatID: *telegramChatID,
	}
}
