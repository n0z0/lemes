package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func handleLureDashboard(w http.ResponseWriter, r *http.Request) {
	pubURL := *publicURL
	if pubURL == "" || strings.Contains(pubURL, "localhost") || strings.Contains(pubURL, "127.0.0.1") {
		if r.Host != "" && !strings.HasPrefix(r.Host, "localhost") && !strings.HasPrefix(r.Host, "127.0.0.1") {
			scheme := "http"
			if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
				scheme = "https"
			}
			pubURL = fmt.Sprintf("%s://%s", scheme, r.Host)
		} else if localIP != "" && localIP != "127.0.0.1" {
			pubURL = fmt.Sprintf("http://%s%s", localIP, *port)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	html := strings.ReplaceAll(lureDashboardHTML, "{{PUBLIC_URL}}", pubURL)
	w.Write([]byte(html))
}

func handleDownloadLureHTML(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = "default_token"
	}

	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		fileName = "internal_vpn_credentials.html"
	}

	customBase := r.URL.Query().Get("base_url")
	pubURL := *publicURL
	if customBase != "" {
		pubURL = strings.TrimRight(customBase, "/")
	} else if pubURL == "" || strings.Contains(pubURL, "localhost") || strings.Contains(pubURL, "127.0.0.1") {
		if r.Host != "" && !strings.HasPrefix(r.Host, "localhost") && !strings.HasPrefix(r.Host, "127.0.0.1") {
			scheme := "http"
			if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
				scheme = "https"
			}
			pubURL = fmt.Sprintf("%s://%s", scheme, r.Host)
		} else if localIP != "" && localIP != "127.0.0.1" {
			pubURL = fmt.Sprintf("http://%s%s", localIP, *port)
		}
	}

	beaconURL := fmt.Sprintf("%s/beacon/pixel.png?token=%s&file=%s", pubURL, url.QueryEscape(token), url.QueryEscape(fileName))
	telemetryURL := fmt.Sprintf("%s/beacon/telemetry", pubURL)

	content := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Internal Corporate VPN Access & Configuration</title>
    <meta charset="UTF-8">
</head>
<body style="font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f8; color: #333;">
    <div style="background: #fff; border: 1px solid #ddd; padding: 30px; border-radius: 8px; max-width: 650px; margin: auto;">
        <h2 style="color: #0b4f8c; margin-top: 0;">Enterprise Network Access Credentials</h2>
        <p><strong>Confidential Notice:</strong> For Authorized Staff Use Only.</p>
        <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
        <table style="width: 100%%; border-collapse: collapse;">
            <tr><td style="padding: 8px 0; font-weight: bold;">Gateway Host:</td><td>vpn-gateway.corp.internal</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Protocol:</td><td>WireGuard / OpenVPN</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Assigned User:</td><td>admin.backup</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Default Pass:</td><td><code>P@ssw0rdEnterprise2026!</code></td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Status:</td><td style="color: green; font-weight: bold;">ACTIVE</td></tr>
        </table>
        <p style="margin-top: 25px; font-size: 13px; color: #666;">Silakan gunakan sertifikat yang terlampir untuk autentikasi ganda.</p>
    </div>

    <!-- Tingkat 1: CTI Passive Beacon (Image Pixel) -->
    <img src="%s" width="1" height="1" style="display:none;" alt="" />

    <!-- Tingkat 2: CTI Advanced Telemetry (Hardware, Timezone & Environment Fingerprint) -->
    <script>
    (function() {
        try {
            var token = %q;
            var file = %q;
            var telemetryUrl = %q;

            var gpuVendor = "Unknown";
            var gpuRenderer = "Unknown";
            try {
                var canvas = document.createElement("canvas");
                var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
                if (gl) {
                    var debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
                    if (debugInfo) {
                        gpuVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || "Unknown";
                        gpuRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || "Unknown";
                    }
                }
            } catch (e) {}

            var payload = {
                token_id: token,
                lure_file: file,
                timezone: (Intl && Intl.DateTimeFormat) ? Intl.DateTimeFormat().resolvedOptions().timeZone : "Unknown",
                screen_resolution: (window.screen.width || 0) + "x" + (window.screen.height || 0),
                color_depth: window.screen.colorDepth || 0,
                cpu_cores: navigator.hardwareConcurrency || 0,
                device_memory_gb: navigator.deviceMemory || 0,
                gpu_renderer: gpuRenderer,
                gpu_vendor: gpuVendor,
                languages: navigator.languages ? Array.prototype.slice.call(navigator.languages) : [navigator.language || ""],
                platform: navigator.platform || (navigator.userAgentData ? navigator.userAgentData.platform : "Unknown"),
                touch_support: (navigator.maxTouchPoints || 0) > 0,
                local_time: new Date().toString()
            };

            var jsonStr = JSON.stringify(payload);

            if (navigator.sendBeacon) {
                var blob = new Blob([jsonStr], { type: "application/json" });
                navigator.sendBeacon(telemetryUrl, blob);
            } else {
                fetch(telemetryUrl, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: jsonStr,
                    mode: "cors"
                }).catch(function() {});
            }
        } catch (err) {}
    })();
    </script>
</body>
</html>`, beaconURL, token, fileName, telemetryURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
}

const lureDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lemes - Honeytoken & Lure Generator</title>
    <style>
        :root {
            --bg: #090d16;
            --surface: #131b2e;
            --accent: #06b6d4;
            --text: #f1f5f9;
            --muted: #94a3b8;
            --border: #1e293b;
            --badge: #0284c7;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
        body { background: var(--bg); color: var(--text); padding: 40px 20px; }
        .container { max-width: 850px; margin: auto; }
        h1 { font-size: 26px; color: var(--accent); margin-bottom: 8px; font-weight: 700; }
        p.subtitle { color: var(--muted); margin-bottom: 30px; font-size: 14px; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 24px; }
        .card h2 { font-size: 18px; margin-bottom: 12px; }
        .badge-pill { display: inline-block; background: rgba(6, 182, 212, 0.15); color: var(--accent); border: 1px solid rgba(6, 182, 212, 0.4); padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 12px; }
        .field { margin-bottom: 16px; }
        label { display: block; font-size: 12px; text-transform: uppercase; color: var(--muted); margin-bottom: 6px; }
        input { width: 100%; padding: 10px; background: #070a12; border: 1px solid var(--border); border-radius: 6px; color: #fff; font-size: 14px; }
        .code-box { background: #05080f; border: 1px solid #1e293b; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 13px; color: #38bdf8; word-break: break-all; margin: 12px 0; }
        .btn { display: inline-block; padding: 10px 18px; background: var(--accent); color: #000; font-weight: 600; text-decoration: none; border-radius: 6px; font-size: 14px; cursor: pointer; border: none; }
        .btn:hover { opacity: 0.9; }
        ol, ul { padding-left: 20px; color: var(--muted); font-size: 14px; line-height: 1.6; }
        li { margin-bottom: 8px; }
        code { background: #05080f; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }
        .tier-box { background: #080f1e; border-left: 3px solid var(--accent); padding: 12px 16px; margin: 12px 0; border-radius: 0 6px 6px 0; font-size: 13px; color: #cbd5e1; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍯 Lemes Honeybeacon Generator</h1>
        <p class="subtitle">Buat Lure File & Honeytoken untuk memancing pelaku dan mengungkap IP, OS, Timezone & Spesifikasi Mesin Workstation aslinya.</p>

        <div class="card">
            <span class="badge-pill">Tingkat 2 Telemetry Aktif</span>
            <h2>1. Konfigurasi & Unduh Umpan (Lure File)</h2>
            <div class="tier-box">
                File HTML ini memuat <strong>Tingkat 1 (Passive Pixel)</strong> dan <strong>Tingkat 2 (JS Telemetry)</strong>. Saat dibuka di browser pelaku, ia otomatis merekam <strong>Real IP, Timezone, Model GPU, CPU Cores, RAM, dan Resolusi Layar</strong> ke log CTI!
            </div>
            <div class="field">
                <label>Alamat Listener / Base URL (IP LAN Komputer / Domain Publik Tunnel)</label>
                <input type="text" id="baseUrlInput" value="{{PUBLIC_URL}}" oninput="updateSnippet()">
            </div>
            <div class="field">
                <label>Token Identifier (Unik per file/target)</label>
                <input type="text" id="tokenInput" value="sftp_vpn_leak_01" oninput="updateSnippet()">
            </div>
            <div class="field">
                <label>Nama File Lure Decoy</label>
                <input type="text" id="fileInput" value="internal_vpn_credentials.html" oninput="updateSnippet()">
            </div>
            <button class="btn" onclick="downloadLure()">Unduh File Lure HTML Siap Pakai (.html)</button>
        </div>

        <div class="card">
            <h2>2. URL Beacon / Tracking Pixel (Tingkat 1)</h2>
            <p style="color: var(--muted); font-size: 13px;">Gunakan link ini untuk disisipkan ke dokumen Word, PDF, Web bug, atau Markdown:</p>
            <div class="code-box" id="urlBox"></div>
        </div>

        <div class="card">
            <h2>3. Contoh Penyisipan ke Dokumen Lain</h2>
            <ul>
                <li><strong>Markdown (README di honeypot SFTP scp):</strong><br>
                    <div class="code-box" id="mdBox"></div>
                </li>
                <li><strong>Microsoft Word / LibreOffice (.docx):</strong> Buka Word -> Insert Image via URL / External Link, lalu arahkan ke URL Beacon di atas. Ketika dokumen dibuka oleh penyerang, Word akan memuat gambar tersebut secara otomatis dari workstation penyerang!</li>
            </ul>
        </div>
    </div>

    <script>
        function updateSnippet() {
            const token = encodeURIComponent(document.getElementById('tokenInput').value);
            const file = encodeURIComponent(document.getElementById('fileInput').value);
            const baseUrl = document.getElementById('baseUrlInput').value.replace(/\/+$/, '');
            const beaconUrl = baseUrl + "/beacon/pixel.png?token=" + token + "&file=" + file;

            document.getElementById('urlBox').textContent = beaconUrl;
            document.getElementById('mdBox').textContent = '![](' + beaconUrl + ')';
        }

        function downloadLure() {
            const token = encodeURIComponent(document.getElementById('tokenInput').value);
            const file = encodeURIComponent(document.getElementById('fileInput').value);
            const baseUrl = document.getElementById('baseUrlInput').value.replace(/\/+$/, '');
            window.location.href = baseUrl + "/lure/download/html?token=" + token + "&file=" + file + "&base_url=" + encodeURIComponent(baseUrl);
        }

        updateSnippet();
    </script>
</body>
</html>`
