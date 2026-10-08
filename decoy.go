package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func handleDecoyPortal(w http.ResponseWriter, r *http.Request) {
	clientIP, clientPort := extractClientIP(r)

	// Jika POST request -> Penyerang mencoba login atau kirim form kredensial
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		username := r.Form.Get("username")
		if username == "" {
			username = r.Form.Get("user")
		}
		if username == "" {
			username = r.Form.Get("email")
		}

		password := r.Form.Get("password")
		if password == "" {
			password = r.Form.Get("pass")
		}

		// Jika input dalam JSON body
		if username == "" && strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			var bodyMap map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&bodyMap)
			if u, ok := bodyMap["username"].(string); ok {
				username = u
			}
			if p, ok := bodyMap["password"].(string); ok {
				password = p
			}
		}

		event := &LemesCTIEvent{
			Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
			SensorID:       *sensorID,
			EventType:      "DECOY_LOGIN_ATTEMPT",
			ClientIP:       clientIP,
			ClientPort:     clientPort,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Referer:        r.Referer(),
			Method:         r.Method,
			URLPath:        r.URL.Path,
			Credentials: &DecoyCredentials{
				Username: username,
				Password: password,
			},
			Headers: extractKeyHeaders(r),
			Mitre: MitreAttackInfo{
				Tactic:    "Credential Access",
				Technique: "Brute Force: Password Guessing / Credential Stuffing",
				ID:        "T1110",
			},
		}

		if ctiLogger != nil {
			ctiLogger.asyncEnrichAndLog(event)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"status":"error","message":"Invalid Active Directory Single Sign-On credentials or expired security token"}`)
		return
	}

	// GET request -> Tampilkan decoy portal login
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(decoyHTML))
}

func handleDecoyAPI(w http.ResponseWriter, r *http.Request) {
	clientIP, clientPort := extractClientIP(r)

	event := &LemesCTIEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		SensorID:       *sensorID,
		EventType:      "DECOY_PROBE_REQUEST",
		ClientIP:       clientIP,
		ClientPort:     clientPort,
		UserAgent:      r.UserAgent(),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		Referer:        r.Referer(),
		Method:         r.Method,
		URLPath:        r.URL.Path,
		Headers:        extractKeyHeaders(r),
		Mitre: MitreAttackInfo{
			Tactic:    "Discovery",
			Technique: "Cloud Service Discovery / API Enumeration",
			ID:        "T1526",
		},
	}

	if ctiLogger != nil {
		ctiLogger.asyncEnrichAndLog(event)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `{"error":"Forbidden","message":"API gateway requires mutual TLS authentication and signed bearer token"}`)
}

const decoyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Gateway - Internal Staff Sign In</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --danger: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; }
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            width: 100%;
            max-width: 420px;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 36px 32px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.4);
        }
        .header {
            text-align: center;
            margin-bottom: 28px;
        }
        .badge {
            display: inline-block;
            background: rgba(59, 130, 246, 0.15);
            color: var(--accent);
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 12px;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }
        .header h1 {
            font-size: 20px;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 6px;
        }
        .header p {
            color: var(--text-muted);
            font-size: 13px;
        }
        .form-group {
            margin-bottom: 18px;
        }
        .form-group label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-muted);
            margin-bottom: 6px;
        }
        .form-group input {
            width: 100%;
            padding: 10px 14px;
            background: #0b1120;
            border: 1px solid var(--border);
            border-radius: 6px;
            color: #fff;
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s;
        }
        .form-group input:focus {
            border-color: var(--accent);
        }
        .btn-submit {
            width: 100%;
            padding: 11px;
            background: var(--accent);
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
            margin-top: 6px;
        }
        .btn-submit:hover {
            background: var(--accent-hover);
        }
        .alert {
            display: none;
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.4);
            color: var(--danger);
            padding: 10px 12px;
            border-radius: 6px;
            font-size: 13px;
            margin-bottom: 16px;
        }
        .footer {
            margin-top: 26px;
            text-align: center;
            font-size: 11px;
            color: var(--text-muted);
            line-height: 1.5;
            border-top: 1px solid var(--border);
            padding-top: 16px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span class="badge">Decoy Protected Network</span>
            <h1>Enterprise Staff Portal</h1>
            <p>Single Sign-On (Active Directory & 2FA)</p>
        </div>
        <div id="alertBox" class="alert"></div>
        <form id="loginForm" method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username / Corporate ID</label>
                <input type="text" id="username" name="username" placeholder="user@company.internal" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="••••••••••••" required>
            </div>
            <button type="submit" class="btn-submit">Sign In to Workstation</button>
        </form>
        <div class="footer">
            Unauthorized access or scanning of this system is monitored and recorded for security intelligence compliance (ISO/IEC 27001).
        </div>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const btn = document.querySelector('.btn-submit');
            const alertBox = document.getElementById('alertBox');
            btn.disabled = true;
            btn.textContent = 'Verifying with Active Directory...';
            alertBox.style.display = 'none';

            const formData = new FormData(this);
            try {
                const resp = await fetch('/login', {
                    method: 'POST',
                    body: new URLSearchParams(formData)
                });
                const data = await resp.json();
                alertBox.textContent = data.message || 'Authentication failed: Invalid credentials.';
                alertBox.style.display = 'block';
            } catch (err) {
                alertBox.textContent = 'Connection timeout with Domain Controller.';
                alertBox.style.display = 'block';
            } finally {
                btn.disabled = false;
                btn.textContent = 'Sign In to Workstation';
            }
        });
    </script>
</body>
</html>`
