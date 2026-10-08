# lemes 🍯

> **Lightweight Honeybeacon & Decoy Web Server for Cyber Threat Intelligence (CTI) & Attacker Attribution.**

`lemes` adalah komponen penangkap sinyal (*beacon receiver* & *web decoy*) yang melengkapi ekosistem honeypot ([synwatcher](https://github.com/n0z0/synwatcher), [scp](https://github.com/n0z0/scp), dan [cachedb](https://github.com/n0z0/cachedb)) untuk melakukan **atribusi objek/manusia (human & workstation attribution)** secara akurat.

---

## 🎯 Peran dalam Ekosistem CTI

```
+-----------------------------------------------------------------------------------+
| 1. RECONNAISSANCE                                                                 |
|    synwatcher mendeteksi port scan TCP/UDP dari IP Penyerang.                     |
|    -> Log MITRE T1046: Network Service Discovery                                 |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
| 2. INGRESS & EXFILTRATION                                                         |
|    Penyerang masuk ke honeypot SFTP (scp :60606) & mendownload file umpan/lure:   |
|    "confidential_vpn_credentials.html"                                            |
|    -> Log MITRE T1005: Data from Local System (scp_cti.jsonl)                     |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
| 3. HUMAN ATTRBUTION & EXECUTION (lemes)                                           |
|    Penyerang membuka file dokumen hasil curian di laptop/workstation aslinya!     |
|    Dokumen diam-diam memanggil beacon pixel:                                      |
|    GET /beacon/pixel.png?token=vpn_leak_01                                        |
|    -> lemes merekam: Real IP, User-Agent, Accept-Language, OS Platform            |
|    -> Log MITRE T1204.002: User Execution (lemes_cti.jsonl)                       |
+-----------------------------------------------------------------------------------+
```

---

## ✨ Fitur Utama

1. **Invisible 1x1 Beacon Tracking Pixel**:
   - Menyajikan 1x1 transparent PNG (`/beacon/pixel.png`, `/track.png`, `/b/{token}`).
   - Header anti-cache ketat (`no-cache, no-store, must-revalidate`).
2. **Forensik & Atribusi Lengkap**:
   - Ekstraksi IP asli penyerang (dukungan `CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`).
   - Ekstraksi `User-Agent` (mengenali software pembuka: MS Word, Excel, Adobe Acrobat, Browser, curl).
   - Ekstraksi `Accept-Language` (menganalisis bahasa sistem/lokal pelaku: `id-ID`, `ru-RU`, `zh-CN`, `en-US`).
   - Ekstraksi Client Hints (`Sec-Ch-Ua`, `Sec-Ch-Ua-Platform`).
3. **Decoy Login Portal & API Traps**:
   - Menyajikan halaman login perusahaan palsu (*Single Sign-On Portal*) pada `/`, `/login`, `/portal`.
   - Menjebak dan merekam percobaan brute force / credential stuffing (MITRE T1110).
4. **Lure & Token Generator Bawaan**:
   - Akses `/lure` di browser untuk membuat token dan mengunduh file dokumen umpan HTML siap pakai yang langsung bisa ditaruh di SFTP honeypot `scp`.
5. **Integrasi cacheDB (Opsional)**:
   - Otomatis menyimpan entri ancaman ke cache memory via gRPC [cachedb](https://github.com/n0z0/cachedb).
6. **Structured CTI Log (JSON Lines)**:
   - Format standar `lemes_cti.jsonl` yang siap dikonsumsi SIEM, ELK, atau script analisa intelijen.

---

## 🚀 Instalasi Cepat

### Windows (PowerShell)
Jalankan di PowerShell:
```powershell
irm https://raw.githubusercontent.com/n0z0/lemes/main/install.ps1 | iex
```

### Linux (Bash)
Jalankan di terminal Linux:
```bash
curl -fsSL https://raw.githubusercontent.com/n0z0/lemes/main/install.sh | bash
```

---

## 🛠️ Penggunaan

### 1. Menjalankan Server
```bash
# Menjalankan pada port default 8080
lemes -port :8080

# Menjalankan dengan integrasi cachedb dan CTI log custom
lemes -port :8080 -ctilog /var/log/lemes_cti.jsonl -cachedb 127.0.0.1:50051 -public-url http://cti.domain.com:8080
```

### 2. Opsi Perintah (CLI Flags)
| Flag | Tipe | Default | Keterangan |
| :--- | :--- | :--- | :--- |
| `-port` | string | `:8080` | Port listen HTTP server |
| `-ctilog` | string | `lemes_cti.jsonl` | Lokasi file output log CTI (JSONL) |
| `-sensor-id` | string | `hostname` | Identitas unik sensor node ini |
| `-cachedb` | string | `""` | Alamat gRPC cacheDB opsional (`host:port`) |
| `-public-url` | string | `http://localhost<port>` | URL publik yang bisa dijangkau oleh penyerang |
| `-version` | bool | `false` | Tampilkan versi lemes |

---

## 📋 Endpoint Server

| Path | Metode | Keterangan |
| :--- | :--- | :--- |
| `/beacon/pixel.png` | GET | Tracking pixel 1x1 transparent PNG (Beacon) |
| `/b/{token}` | GET | Format ringkas pemanggil beacon token |
| `/login`, `/portal` | GET / POST | Decoy Corporate Login Portal (menjebak kredensial) |
| `/api/*` | ANY | Decoy API probes trap |
| `/lure` | GET | Dashboard generator token & file umpan |
| `/lure/download/html` | GET | Unduh file HTML lure siap sebar |
| `/ping` | GET | Health-check endpoint |

---

## 🧪 Contoh Output Log CTI (`lemes_cti.jsonl`)

### Event 1: Penyerang Membuka File Lure (Beacon Triggered)
```json
{
  "timestamp": "2026-10-08T09:56:46.0487704Z",
  "sensor_id": "sensor-srv-01",
  "event_type": "BEACON_TRIGGERED",
  "client_ip": "182.253.14.92",
  "client_port": 56896,
  "user_agent": "Microsoft Office Word 2021 (Windows NT 10.0; Win64; x64)",
  "accept_language": "id-ID,id;q=0.9,en-US;q=0.8",
  "method": "GET",
  "url_path": "/beacon/pixel.png",
  "token_id": "vpn_backup_leak_01",
  "lure_file": "confidential_vpn.docx",
  "mitre_attack": {
    "tactic": "Execution",
    "technique": "User Execution: Malicious File / Lure Opened",
    "technique_id": "T1204.002"
  }
}
```

### Event 2: Penyerang Mencoba Login ke Web Decoy
```json
{
  "timestamp": "2026-10-08T09:57:11.6728871Z",
  "sensor_id": "sensor-srv-01",
  "event_type": "DECOY_LOGIN_ATTEMPT",
  "client_ip": "182.253.14.92",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "method": "POST",
  "url_path": "/login",
  "credentials": {
    "username": "admin.internal",
    "password": "Password123!"
  },
  "mitre_attack": {
    "tactic": "Credential Access",
    "technique": "Brute Force: Password Guessing / Credential Stuffing",
    "technique_id": "T1110"
  }
}
```

---

## 📄 Lisensi
[GPL-3.0 License](LICENSE)
