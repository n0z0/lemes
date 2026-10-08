package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// WebhookConfig menyimpan konfigurasi alerting eksternal
type WebhookConfig struct {
	URL            string
	WebhookType    string // "generic", "discord", "telegram", "slack"
	TelegramChatID string
}

var globalWebhookCfg WebhookConfig

// DispatchWebhook mengirimkan alert intelijen ancaman secara asinkron via Goroutine
func DispatchWebhook(event *LemesCTIEvent, cfg WebhookConfig) {
	if cfg.URL == "" || event == nil {
		return
	}

	// Goroutine terisolasi: zero-latency impact terhadap response HTTP klien
	go func(evt *LemesCTIEvent, c WebhookConfig) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		var payloadBytes []byte
		var targetURL = c.URL
		var contentType = "application/json"

		wType := strings.ToLower(c.WebhookType)
		if wType == "generic" {
			// Auto-detect berdasarkan URL
			if strings.Contains(c.URL, "discord.com/api/webhooks") {
				wType = "discord"
			} else if strings.Contains(c.URL, "api.telegram.org") {
				wType = "telegram"
			} else if strings.Contains(c.URL, "hooks.slack.com") {
				wType = "slack"
			}
		}

		switch wType {
		case "discord":
			payloadBytes = formatDiscordPayload(evt)
		case "telegram":
			payloadBytes, targetURL = formatTelegramPayload(evt, c)
		case "slack":
			payloadBytes = formatSlackPayload(evt)
		default: // generic SIEM / SOAR endpoint
			data, err := json.Marshal(evt)
			if err != nil {
				return
			}
			payloadBytes = data
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewBuffer(payloadBytes))
		if err != nil {
			log.Printf("[WEBHOOK ERROR] Gagal membuat request: %v", err)
			return
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("User-Agent", "lemes-soc-webhook/1.0")

		client := &http.Client{Timeout: 4 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[WEBHOOK ALERT] Gagal mengirim alert ke %s: %v", wType, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("[WEBHOOK DISPATCH] Berhasil mengirim alert SOC [%s] ke %s", evt.EventType, wType)
		} else {
			log.Printf("[WEBHOOK ALERT] Server merespons non-2xx status: %d", resp.StatusCode)
		}
	}(event, cfg)
}

func formatDiscordPayload(evt *LemesCTIEvent) []byte {
	color := 0x3498DB // Blue info
	if evt.Severity == "CRITICAL" || evt.ThreatScore >= 90 {
		color = 0xE74C3C // Red
	} else if evt.Severity == "HIGH" || evt.ThreatScore >= 70 {
		color = 0xE67E22 // Orange
	} else if evt.Severity == "MEDIUM" {
		color = 0xF1C40F // Yellow
	}

	title := fmt.Sprintf("🚨 SOC ALERT: [%s] %s", evt.Severity, evt.EventType)
	if evt.Deanonymized {
		title = fmt.Sprintf("🎯 CRITICAL DE-ANONYMIZATION: Attacker Unmasked! [%s]", evt.ClientIP)
	}

	desc := fmt.Sprintf("**Sensor:** `%s`\n**MITRE ATT&CK:** `%s - %s (%s)`",
		evt.SensorID, evt.Mitre.Tactic, evt.Mitre.Technique, evt.Mitre.ID)

	fields := []map[string]interface{}{
		{"name": "Client IP", "value": fmt.Sprintf("`%s`", evt.ClientIP), "inline": true},
		{"name": "Threat Score", "value": fmt.Sprintf("**%d / 100** (%s)", evt.ThreatScore, evt.Severity), "inline": true},
		{"name": "Kill Chain Phase", "value": evt.KillChainPhase, "inline": true},
	}

	if evt.ReverseDNS != "" {
		fields = append(fields, map[string]interface{}{
			"name": "Reverse DNS (PTR)", "value": fmt.Sprintf("`%s`", evt.ReverseDNS), "inline": true,
		})
	}
	if evt.TokenID != "" {
		fields = append(fields, map[string]interface{}{
			"name": "Token / Canary ID", "value": fmt.Sprintf("`%s`", evt.TokenID), "inline": true,
		})
	}
	if evt.LureFile != "" {
		fields = append(fields, map[string]interface{}{
			"name": "Lure Document", "value": fmt.Sprintf("`%s`", evt.LureFile), "inline": true,
		})
	}
	if evt.ScannerIP != "" {
		fields = append(fields, map[string]interface{}{
			"name": "Previous Scanner IP (L4/L7)", "value": fmt.Sprintf("`%s`", evt.ScannerIP), "inline": true,
		})
	}
	if evt.UserAgent != "" {
		uaShort := evt.UserAgent
		if len(uaShort) > 75 {
			uaShort = uaShort[:75] + "..."
		}
		fields = append(fields, map[string]interface{}{
			"name": "User-Agent", "value": fmt.Sprintf("`%s`", uaShort), "inline": false,
		})
	}
	if evt.Credentials != nil && evt.Credentials.Username != "" {
		fields = append(fields, map[string]interface{}{
			"name": "Harvested Creds", "value": fmt.Sprintf("User: `%s` | Pass: `%s`", evt.Credentials.Username, evt.Credentials.Password), "inline": false,
		})
	}

	payload := map[string]interface{}{
		"username": "lemes Honeybeacon SOC Bot",
		"embeds": []map[string]interface{}{
			{
				"title":       title,
				"description": desc,
				"color":       color,
				"fields":      fields,
				"footer":      map[string]string{"text": fmt.Sprintf("Timestamp UTC: %s", evt.Timestamp)},
			},
		},
	}

	data, _ := json.Marshal(payload)
	return data
}

func formatTelegramPayload(evt *LemesCTIEvent, cfg WebhookConfig) ([]byte, string) {
	msg := fmt.Sprintf("🚨 *SOC THREAT INTEL ALERT*\n\n"+
		"*Event:* `%s`\n"+
		"*Severity:* `%s` (%d/100)\n"+
		"*Client IP:* `%s`\n",
		evt.EventType, evt.Severity, evt.ThreatScore, evt.ClientIP)

	if evt.ReverseDNS != "" {
		msg += fmt.Sprintf("*Reverse DNS:* `%s`\n", evt.ReverseDNS)
	}
	if evt.TokenID != "" {
		msg += fmt.Sprintf("*Token ID:* `%s`\n", evt.TokenID)
	}
	if evt.LureFile != "" {
		msg += fmt.Sprintf("*Lure File:* `%s`\n", evt.LureFile)
	}
	if evt.Deanonymized && evt.ScannerIP != "" {
		msg += fmt.Sprintf("🎯 *ATTRIBUTION UNMASKED!*\n*Scanner IP:* `%s` ➔ *Real IP:* `%s`\n", evt.ScannerIP, evt.ClientIP)
	}
	msg += fmt.Sprintf("*MITRE:* `%s` (%s)\n*Time:* `%s`", evt.Mitre.Technique, evt.Mitre.ID, evt.Timestamp)

	payload := map[string]interface{}{
		"chat_id":    cfg.TelegramChatID,
		"text":       msg,
		"parse_mode": "Markdown",
	}

	target := cfg.URL
	if !strings.Contains(target, "/sendMessage") {
		if !strings.HasSuffix(target, "/") {
			target += "/"
		}
		target += "sendMessage"
	}

	data, _ := json.Marshal(payload)
	return data, target
}

func formatSlackPayload(evt *LemesCTIEvent) []byte {
	color := "#36a64f"
	if evt.ThreatScore >= 80 {
		color = "#danger"
	} else if evt.ThreatScore >= 50 {
		color = "#warning"
	}

	text := fmt.Sprintf("*[SOC ALERT - %s]* %s triggered by `%s`", evt.Severity, evt.EventType, evt.ClientIP)
	if evt.Deanonymized {
		text = fmt.Sprintf("🎯 *[CRITICAL ATTRIBUTION LEAK]* Attacker Workstation `%s` opened stolen lure `%s`!", evt.ClientIP, evt.LureFile)
	}

	payload := map[string]interface{}{
		"text": text,
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"fields": []map[string]interface{}{
					{"title": "Threat Score", "value": fmt.Sprintf("%d / 100", evt.ThreatScore), "short": true},
					{"title": "MITRE Technique", "value": fmt.Sprintf("%s (%s)", evt.Mitre.Technique, evt.Mitre.ID), "short": true},
					{"title": "Reverse DNS", "value": evt.ReverseDNS, "short": true},
					{"title": "Token ID", "value": evt.TokenID, "short": true},
				},
				"footer": "lemes Honeybeacon",
				"ts":     time.Now().Unix(),
			},
		},
	}

	data, _ := json.Marshal(payload)
	return data
}
