package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func handleLureDashboard(w http.ResponseWriter, r *http.Request) {
	pubURL := *publicURL
	if pubURL == "" {
		pubURL = fmt.Sprintf("http://%s", r.Host)
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

	pubURL := *publicURL
	if pubURL == "" {
		pubURL = fmt.Sprintf("http://%s", r.Host)
	}

	beaconURL := fmt.Sprintf("%s/beacon/pixel.png?token=%s&file=%s", pubURL, url.QueryEscape(token), url.QueryEscape(fileName))

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
    <!-- CTI Honeytoken Beacon (Invisible) -->
    <img src="%s" width="1" height="1" style="display:none;" alt="" />
</body>
</html>`, beaconURL)

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
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
        body { background: var(--bg); color: var(--text); padding: 40px 20px; }
        .container { max-width: 850px; margin: auto; }
        h1 { font-size: 26px; color: var(--accent); margin-bottom: 8px; font-weight: 700; }
        p.subtitle { color: var(--muted); margin-bottom: 30px; font-size: 14px; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 24px; }
        .card h2 { font-size: 18px; margin-bottom: 12px; }
        .field { margin-bottom: 16px; }
        label { display: block; font-size: 12px; text-transform: uppercase; color: var(--muted); margin-bottom: 6px; }
        input { width: 100%; padding: 10px; background: #070a12; border: 1px solid var(--border); border-radius: 6px; color: #fff; font-size: 14px; }
        .code-box { background: #05080f; border: 1px solid #1e293b; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 13px; color: #38bdf8; word-break: break-all; margin: 12px 0; }
        .btn { display: inline-block; padding: 10px 18px; background: var(--accent); color: #000; font-weight: 600; text-decoration: none; border-radius: 6px; font-size: 14px; cursor: pointer; border: none; }
        .btn:hover { opacity: 0.9; }
        ol, ul { padding-left: 20px; color: var(--muted); font-size: 14px; line-height: 1.6; }
        li { margin-bottom: 8px; }
        code { background: #05080f; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍯 Lemes Honeybeacon Generator</h1>
        <p class="subtitle">Buat Lure File & Honeytoken untuk memancing pelaku dan mengungkap IP / OS Workstation aslinya.</p>

        <div class="card">
            <h2>1. Konfigurasi Token</h2>
            <div class="field">
                <label>Token Identifier (Unik per file/target)</label>
                <input type="text" id="tokenInput" value="sftp_vpn_leak_01" oninput="updateSnippet()">
            </div>
            <div class="field">
                <label>Nama File Lure Decoy</label>
                <input type="text" id="fileInput" value="vpn_credentials.html" oninput="updateSnippet()">
            </div>
            <button class="btn" onclick="downloadLure()">Unduh File Lure HTML Siap Pakai (.html)</button>
        </div>

        <div class="card">
            <h2>2. URL Beacon / Tracking Pixel</h2>
            <p style="color: var(--muted); font-size: 13px;">Gunakan link ini untuk disisipkan ke dokumen Word, PDF, Web bug, atau Markdown:</p>
            <div class="code-box" id="urlBox"></div>
        </div>

        <div class="card">
            <h2>3. Contoh Penyisipan ke Dokumen</h2>
            <ul>
                <li><strong>HTML / Web Bug:</strong> Masukkan tag berikut di dokumen HTML atau template:<br>
                    <div class="code-box" id="htmlBox"></div>
                </li>
                <li><strong>Markdown (README di honeypot SFTP scp):</strong><br>
                    <div class="code-box" id="mdBox"></div>
                </li>
                <li><strong>Microsoft Word / LibreOffice (.docx):</strong> Buka Word -> Insert Image via URL / External Link, lalu arahkan ke URL Beacon di atas. Ketika dokumen dibuka oleh penyerang, Word akan memuat gambar tersebut secara otomatis dari workstation penyerang!</li>
            </ul>
        </div>
    </div>

    <script>
        const baseUrl = "{{PUBLIC_URL}}";

        function updateSnippet() {
            const token = encodeURIComponent(document.getElementById('tokenInput').value);
            const file = encodeURIComponent(document.getElementById('fileInput').value);
            const beaconUrl = baseUrl + "/beacon/pixel.png?token=" + token + "&file=" + file;

            document.getElementById('urlBox').textContent = beaconUrl;
            document.getElementById('htmlBox').textContent = '<img src="' + beaconUrl + '" width="1" height="1" style="display:none;" />';
            document.getElementById('mdBox').textContent = '![](' + beaconUrl + ')';
        }

        function downloadLure() {
            const token = encodeURIComponent(document.getElementById('tokenInput').value);
            const file = encodeURIComponent(document.getElementById('fileInput').value);
            window.location.href = baseUrl + "/lure/download/html?token=" + token + "&file=" + file;
        }

        updateSnippet();
    </script>
</body>
</html>`
