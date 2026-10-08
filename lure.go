package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

func pdfEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}

// loadContentLines membaca berkas content/CONTENT.md atau ./CONTENT.md
func loadContentLines() []string {
	candidates := []string{
		filepath.Join("content", "CONTENT.md"),
		filepath.Join("..", "content", "CONTENT.md"),
		"CONTENT.md",
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			lines := strings.Split(string(data), "\n")
			var res []string
			for _, l := range lines {
				res = append(res, strings.TrimRight(l, "\r"))
			}
			return res
		}
	}

	// Fallback default jika file tidak ditemukan
	return []string{
		"# CONFIDENTIAL - ENTERPRISE ACCESS & INFRASTRUCTURE LOGS",
		"Dokumen ini memuat data internal sensitif. Dilarang menyebarluaskan dokumen ini tanpa otorisasi.",
		"## 1. Akses Portal Komunikasi Internal",
		"- Meeting Portal: https://10.0.0.1:8443/group/it-briefing",
		"- Admin Account: admin / admin123",
		"- Gateway VPN: vpn-gw.corp.internal (WireGuard)",
		"## 2. Catatan Integritas",
		"Dokumen ini diproteksi oleh sistem verifikasi keamanan jaringan.",
	}
}

// getDualBeaconURLs menghasilkan URL Beacon Utama (Cloudflare / Public) dan URL Beacon LAN (IP Lokal)
func getDualBeaconURLs(pubURL, token, fileName string) (string, string) {
	primary := fmt.Sprintf("%s/beacon/pixel.png?token=%s&file=%s&channel=primary", pubURL, url.QueryEscape(token), url.QueryEscape(fileName))

	var lan string
	if localIP != "" && localIP != "127.0.0.1" && !strings.Contains(pubURL, localIP) {
		lan = fmt.Sprintf("http://%s%s/beacon/pixel.png?token=%s&file=%s&channel=lan", localIP, *port, url.QueryEscape(token), url.QueryEscape(fileName))
	}
	return primary, lan
}

func resolvePublicBaseURL(r *http.Request, customBase string) string {
	if customBase != "" {
		return strings.TrimRight(customBase, "/")
	}
	pubURL := *publicURL
	if pubURL == "" || strings.Contains(pubURL, "localhost") || strings.Contains(pubURL, "127.0.0.1") {
		if r.Host != "" && !strings.HasPrefix(r.Host, "localhost") && !strings.HasPrefix(r.Host, "127.0.0.1") {
			scheme := "http"
			if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
				scheme = "https"
			}
			return fmt.Sprintf("%s://%s", scheme, r.Host)
		} else if localIP != "" && localIP != "127.0.0.1" {
			return fmt.Sprintf("http://%s%s", localIP, *port)
		}
	}
	return pubURL
}

func handleLureDashboard(w http.ResponseWriter, r *http.Request) {
	pubURL := resolvePublicBaseURL(r, "")
	lanURL := ""
	if localIP != "" && localIP != "127.0.0.1" {
		lanURL = fmt.Sprintf("http://%s%s", localIP, *port)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	html := strings.ReplaceAll(lureDashboardHTML, "{{PUBLIC_URL}}", pubURL)
	html = strings.ReplaceAll(html, "{{LAN_URL}}", lanURL)
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

	pubURL := resolvePublicBaseURL(r, r.URL.Query().Get("base_url"))
	primaryBeacon, lanBeacon := getDualBeaconURLs(pubURL, token, fileName)
	contentLines := loadContentLines()

	var bodyHTML strings.Builder
	for _, line := range contentLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "# ") {
			bodyHTML.WriteString(fmt.Sprintf(`<h2 style="color: #0b4f8c; margin-top: 0;">%s</h2>`, xmlEscape(strings.TrimPrefix(trimmed, "# "))))
		} else if strings.HasPrefix(trimmed, "## ") {
			bodyHTML.WriteString(fmt.Sprintf(`<h3 style="color: #1e293b; margin-top: 20px;">%s</h3>`, xmlEscape(strings.TrimPrefix(trimmed, "## "))))
		} else if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			bodyHTML.WriteString(fmt.Sprintf(`<li style="margin-bottom: 6px;">%s</li>`, xmlEscape(strings.TrimSpace(trimmed[2:]))))
		} else {
			bodyHTML.WriteString(fmt.Sprintf(`<p style="color: #475569; line-height: 1.6;">%s</p>`, xmlEscape(trimmed)))
		}
	}

	telemetryURLPrimary := fmt.Sprintf("%s/beacon/telemetry?src=primary", pubURL)
	telemetryURLLan := ""
	if lanBeacon != "" {
		telemetryURLLan = fmt.Sprintf("http://%s%s/beacon/telemetry?src=lan", localIP, *port)
	}

	lanPixelTag := ""
	if lanBeacon != "" {
		lanPixelTag = fmt.Sprintf(`<img src="%s" width="1" height="1" style="display:none;" alt="" />`, lanBeacon)
	}

	content := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Internal Corporate Security & Access Records</title>
    <meta charset="UTF-8">
</head>
<body style="font-family: Arial, sans-serif; margin: 40px; background-color: #f8fafc; color: #1e293b;">
    <div style="background: #fff; border: 1px solid #e2e8f0; padding: 32px; border-radius: 8px; max-width: 680px; margin: auto; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
        %s
    </div>

    <!-- Dual-Beacon Tracking Pixels (Cloudflare + LAN) -->
    <img src="%s" width="1" height="1" style="display:none;" alt="" />
    %s

    <!-- CTI Advanced Telemetry Fingerprinting -->
    <script>
    (function() {
        try {
            var token = %q;
            var file = %q;
            var urlPrimary = %q;
            var urlLAN = %q;

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
                local_time: new Date().toString()
            };

            var jsonStr = JSON.stringify(payload);

            function sendPayload(endpoint) {
                if (!endpoint) return;
                if (navigator.sendBeacon) {
                    var blob = new Blob([jsonStr], { type: "application/json" });
                    navigator.sendBeacon(endpoint, blob);
                } else {
                    fetch(endpoint, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: jsonStr,
                        mode: "cors"
                    }).catch(function() {});
                }
            }

            sendPayload(urlPrimary);
            if (urlLAN) sendPayload(urlLAN);
        } catch (err) {}
    })();
    </script>
</body>
</html>`, bodyHTML.String(), primaryBeacon, lanPixelTag, token, fileName, telemetryURLPrimary, telemetryURLLan)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
}

func handleDownloadLureDOCX(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = "default_token"
	}

	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		fileName = "Confidential_Network_Access_Credentials.docx"
	}
	if !strings.HasSuffix(strings.ToLower(fileName), ".docx") {
		fileName += ".docx"
	}

	pubURL := resolvePublicBaseURL(r, r.URL.Query().Get("base_url"))
	primaryBeacon, lanBeacon := getDualBeaconURLs(pubURL, token, fileName)
	contentLines := loadContentLines()

	docxBytes, err := generateCanaryDOCX(primaryBeacon, lanBeacon, contentLines)
	if err != nil {
		http.Error(w, "Gagal membuat dokumen DOCX", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	w.WriteHeader(http.StatusOK)
	w.Write(docxBytes)
}

func generateCanaryDOCX(primaryBeacon, lanBeacon string, contentLines []string) ([]byte, error) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	// Build Relationships XML
	relsXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rIdPixel1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="%s" TargetMode="External"/>`, primaryBeacon)
	if lanBeacon != "" {
		relsXML += fmt.Sprintf(`
  <Relationship Id="rIdPixel2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="%s" TargetMode="External"/>`, lanBeacon)
	}
	relsXML += "\n</Relationships>"

	// Build Body XML from contentLines
	var bodyXml strings.Builder
	for _, line := range contentLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "# ") {
			title := strings.TrimPrefix(trimmed, "# ")
			bodyXml.WriteString(fmt.Sprintf(`<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:b/><w:sz w:val="32"/><w:color w:val="B22222"/></w:rPr><w:t>%s</w:t></w:r></w:p>`, xmlEscape(title)))
		} else if strings.HasPrefix(trimmed, "## ") {
			subtitle := strings.TrimPrefix(trimmed, "## ")
			bodyXml.WriteString(fmt.Sprintf(`<w:p><w:r><w:rPr><w:b/><w:sz w:val="26"/><w:color w:val="0B4F8C"/></w:rPr><w:t>%s</w:t></w:r></w:p>`, xmlEscape(subtitle)))
		} else if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			item := strings.TrimSpace(trimmed[2:])
			bodyXml.WriteString(fmt.Sprintf(`<w:p><w:pPr><w:ind w:left="360"/></w:pPr><w:r><w:t>• %s</w:t></w:r></w:p>`, xmlEscape(item)))
		} else {
			bodyXml.WriteString(fmt.Sprintf(`<w:p><w:r><w:t>%s</w:t></w:r></w:p>`, xmlEscape(trimmed)))
		}
	}

	// Append Drawing 1 (Primary / Cloudflare)
	bodyXml.WriteString(`<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="1" cy="1"/><wp:docPr id="1" name="BeaconPrimary"/><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="0" name="pixel1.png"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:link="rIdPixel1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="1" cy="1"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`)

	// Append Drawing 2 (LAN) if available
	if lanBeacon != "" {
		bodyXml.WriteString(`<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="1" cy="1"/><wp:docPr id="2" name="BeaconLAN"/><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="1" name="pixel2.png"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:link="rIdPixel2" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="1" cy="1"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`)
	}
	bodyXml.WriteString(`<w:sectPr/>`)

	docXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
            xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">
  <w:body>
    %s
  </w:body>
</w:document>`, bodyXml.String())

	files := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`,
		"word/_rels/document.xml.rels": relsXML,
		"word/document.xml":            docXML,
	}

	for name, content := range files {
		f, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write([]byte(content)); err != nil {
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func handleDownloadLureXLSX(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = "default_token"
	}

	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		fileName = "Executive_Payroll_2026.xlsx"
	}
	if !strings.HasSuffix(strings.ToLower(fileName), ".xlsx") {
		fileName += ".xlsx"
	}

	pubURL := resolvePublicBaseURL(r, r.URL.Query().Get("base_url"))
	primaryBeacon, lanBeacon := getDualBeaconURLs(pubURL, token, fileName)
	contentLines := loadContentLines()

	xlsxBytes, err := generateCanaryXLSX(primaryBeacon, lanBeacon, contentLines)
	if err != nil {
		http.Error(w, "Gagal membuat dokumen XLSX", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	w.WriteHeader(http.StatusOK)
	w.Write(xlsxBytes)
}

func generateCanaryXLSX(primaryBeacon, lanBeacon string, contentLines []string) ([]byte, error) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	// Rows from contentLines
	var rowsXml strings.Builder
	rowIdx := 1
	for _, line := range contentLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		rowsXml.WriteString(fmt.Sprintf(`<row r="%d"><c r="A%d" t="inlineStr"><is><t>%s</t></is></c></row>`, rowIdx, rowIdx, xmlEscape(trimmed)))
		rowIdx++
	}

	// Drawings relationships
	drawingRels := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdPixel1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="%s" TargetMode="External"/>`, primaryBeacon)
	if lanBeacon != "" {
		drawingRels += fmt.Sprintf(`
  <Relationship Id="rIdPixel2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="%s" TargetMode="External"/>`, lanBeacon)
	}
	drawingRels += "\n</Relationships>"

	// Drawing XML
	drawingXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"
          xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <xdr:oneCellAnchor>
    <xdr:from><xdr:col>0</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>10</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>
    <xdr:ext cx="1" cy="1"/>
    <xdr:pic>
      <xdr:nvPicPr><xdr:cNvPr id="1" name="pixel1.png"/><xdr:cNvPicPr/></xdr:nvPicPr>
      <xdr:blipFill><a:blip r:link="rIdPixel1"/><a:stretch><a:fillRect/></a:stretch></xdr:blipFill>
      <xdr:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="1" cy="1"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></xdr:spPr>
    </xdr:pic>
    <xdr:clientData/>
  </xdr:oneCellAnchor>`

	if lanBeacon != "" {
		drawingXML += `
  <xdr:oneCellAnchor>
    <xdr:from><xdr:col>0</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>11</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>
    <xdr:ext cx="1" cy="1"/>
    <xdr:pic>
      <xdr:nvPicPr><xdr:cNvPr id="2" name="pixel2.png"/><xdr:cNvPicPr/></xdr:nvPicPr>
      <xdr:blipFill><a:blip r:link="rIdPixel2"/><a:stretch><a:fillRect/></a:stretch></xdr:blipFill>
      <xdr:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="1" cy="1"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></xdr:spPr>
    </xdr:pic>
    <xdr:clientData/>
  </xdr:oneCellAnchor>`
	}
	drawingXML += "\n</xdr:wsDr>"

	files := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/drawings/drawing1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`,
		"xl/workbook.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Confidential_Report" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>`,
		"xl/worksheets/_rels/sheet1.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdDraw" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing" Target="../drawings/drawing1.xml"/>
</Relationships>`,
		"xl/worksheets/sheet1.xml": fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheetData>
    %s
  </sheetData>
  <drawing r:id="rIdDraw"/>
</worksheet>`, rowsXml.String()),
		"xl/drawings/_rels/drawing1.xml.rels": drawingRels,
		"xl/drawings/drawing1.xml":            drawingXML,
	}

	for name, content := range files {
		f, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write([]byte(content)); err != nil {
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func handleDownloadLurePDF(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = "default_token"
	}

	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		fileName = "Confidential_Security_Report.pdf"
	}
	if !strings.HasSuffix(strings.ToLower(fileName), ".pdf") {
		fileName += ".pdf"
	}

	pubURL := resolvePublicBaseURL(r, r.URL.Query().Get("base_url"))
	primaryBeacon, lanBeacon := getDualBeaconURLs(pubURL, token, fileName)
	contentLines := loadContentLines()

	pdfBytes := generateCanaryPDF(primaryBeacon, lanBeacon, contentLines)

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	w.WriteHeader(http.StatusOK)
	w.Write(pdfBytes)
}

func generateCanaryPDF(primaryBeacon, lanBeacon string, contentLines []string) []byte {
	var buf bytes.Buffer
	var offsets []int

	writeObj := func(content string) {
		offsets = append(offsets, buf.Len())
		buf.WriteString(content)
	}

	buf.WriteString("%PDF-1.4\n")

	// Obj 1: Catalog
	writeObj("1 0 obj\n<<\n  /Type /Catalog\n  /Pages 2 0 R\n  /OpenAction 4 0 R\n>>\nendobj\n")

	// Obj 2: Pages
	writeObj("2 0 obj\n<<\n  /Type /Pages\n  /Kids [3 0 R]\n  /Count 1\n>>\nendobj\n")

	// Obj 3: Page
	writeObj("3 0 obj\n<<\n  /Type /Page\n  /Parent 2 0 R\n  /MediaBox [0 0 612 792]\n  /Contents 5 0 R\n  /Resources <<\n    /Font <<\n      /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\n      /F2 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n    >>\n  >>\n>>\nendobj\n")

	// Obj 4: Primary Action (URI)
	escapedPrimary := pdfEscape(primaryBeacon)
	if lanBeacon != "" {
		writeObj(fmt.Sprintf("4 0 obj\n<<\n  /Type /Action\n  /S /URI\n  /URI (%s)\n  /Next 6 0 R\n>>\nendobj\n", escapedPrimary))
	} else {
		writeObj(fmt.Sprintf("4 0 obj\n<<\n  /Type /Action\n  /S /URI\n  /URI (%s)\n>>\nendobj\n", escapedPrimary))
	}

	// Obj 5: Stream Content
	var streamBuilder strings.Builder
	streamBuilder.WriteString("BT\n")
	first := true
	for i, l := range contentLines {
		if i > 25 {
			break
		}
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		if first {
			streamBuilder.WriteString(fmt.Sprintf("/F1 14 Tf\n50 740 Td\n(%s) Tj\n", pdfEscape(trimmed)))
			first = false
		} else if strings.HasPrefix(trimmed, "## ") {
			streamBuilder.WriteString(fmt.Sprintf("/F1 11 Tf\n0 -26 Td\n(%s) Tj\n", pdfEscape(strings.TrimPrefix(trimmed, "## "))))
		} else {
			streamBuilder.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -18 Td\n(%s) Tj\n", pdfEscape(trimmed)))
		}
	}
	streamBuilder.WriteString("ET\n")
	streamText := streamBuilder.String()
	writeObj(fmt.Sprintf("5 0 obj\n<< /Length %d >>\nstream\n%sendstream\nendobj\n", len(streamText), streamText))

	// Obj 6: Secondary LAN Action if available
	if lanBeacon != "" {
		escapedLAN := pdfEscape(lanBeacon)
		writeObj(fmt.Sprintf("6 0 obj\n<<\n  /Type /Action\n  /S /URI\n  /URI (%s)\n>>\nendobj\n", escapedLAN))
	}

	startxref := buf.Len()
	buf.WriteString(fmt.Sprintf("xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1))
	for _, off := range offsets {
		buf.WriteString(fmt.Sprintf("%010d 00000 n \n", off))
	}
	buf.WriteString(fmt.Sprintf("trailer\n<<\n  /Size %d\n  /Root 1 0 R\n>>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, startxref))

	return buf.Bytes()
}

func handleDownloadLureURL(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = "default_token"
	}

	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		fileName = "Corporate_VPN_Portal.url"
	}
	if !strings.HasSuffix(strings.ToLower(fileName), ".url") {
		fileName += ".url"
	}

	pubURL := resolvePublicBaseURL(r, r.URL.Query().Get("base_url"))
	primaryBeacon, _ := getDualBeaconURLs(pubURL, token, fileName)
	targetPortalURL := fmt.Sprintf("%s/login", pubURL)

	content := fmt.Sprintf("[InternetShortcut]\r\nURL=%s\r\nIconIndex=0\r\nIconFile=%s\r\n", targetPortalURL, primaryBeacon)

	w.Header().Set("Content-Type", "application/internet-shortcut")
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
        .container { max-width: 900px; margin: auto; }
        h1 { font-size: 26px; color: var(--accent); margin-bottom: 8px; font-weight: 700; }
        p.subtitle { color: var(--muted); margin-bottom: 30px; font-size: 14px; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 24px; }
        .card h2 { font-size: 18px; margin-bottom: 12px; }
        .badge-pill { display: inline-block; background: rgba(6, 182, 212, 0.15); color: var(--accent); border: 1px solid rgba(6, 182, 212, 0.4); padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 12px; }
        .field { margin-bottom: 16px; }
        label { display: block; font-size: 12px; text-transform: uppercase; color: var(--muted); margin-bottom: 6px; }
        input { width: 100%; padding: 10px; background: #070a12; border: 1px solid var(--border); border-radius: 6px; color: #fff; font-size: 14px; }
        .code-box { background: #05080f; border: 1px solid #1e293b; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 13px; color: #38bdf8; word-break: break-all; margin: 12px 0; }
        .btn { display: inline-block; padding: 10px 14px; background: var(--accent); color: #000; font-weight: 600; text-decoration: none; border-radius: 6px; font-size: 13px; cursor: pointer; border: none; text-align: center; }
        .btn:hover { opacity: 0.9; }
        ol, ul { padding-left: 20px; color: var(--muted); font-size: 14px; line-height: 1.6; }
        li { margin-bottom: 8px; }
        code { background: #05080f; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }
        .tier-box { background: #080f1e; border-left: 3px solid var(--accent); padding: 12px 16px; margin: 12px 0; border-radius: 0 6px 6px 0; font-size: 13px; color: #cbd5e1; }
        .tag-dual { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); padding: 2px 6px; border-radius: 4px; font-size: 11px; margin-left: 6px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍯 Lemes Honeybeacon Generator</h1>
        <p class="subtitle">Buat Lure File & Honeytoken untuk memancing pelaku dan mengungkap IP, OS, Timezone & Spesifikasi Mesin Workstation aslinya.</p>

        <div class="card">
            <span class="badge-pill">Dual-Beacon (Cloudflare + LAN) & Custom Content Ready</span>
            <h2>1. Konfigurasi & Unduh Umpan (Lure File)</h2>
            <div class="tier-box">
                ✅ <strong>Dual-Beacon Injection:</strong> Dokumen otomatis disisipi dua target sinyal: Domain Cloudflare (Internet) & IP LAN Lokal.<br>
                ✅ <strong>Dynamic Content:</strong> Isi dokumen langsung dibaca dari <code>content/CONTENT.md</code>. Anda cukup mengedit file tersebut agar konten dokumen Word, Excel, PDF, dan HTML berubah otomatis!
            </div>
            <div class="field">
                <label>Alamat Listener Utama / Public (Cloudflare Tunnel / Domain Publik)</label>
                <input type="text" id="baseUrlInput" value="{{PUBLIC_URL}}" oninput="updateSnippet()">
            </div>
            <div class="field">
                <label>Alamat Listener LAN / IP Lokal <span class="tag-dual">Dual-Beacon</span></label>
                <input type="text" id="lanUrlInput" value="{{LAN_URL}}" disabled style="opacity: 0.8;">
            </div>
            <div class="field">
                <label>Token Identifier (Unik per file/target)</label>
                <input type="text" id="tokenInput" value="sftp_leak_01" oninput="updateSnippet()">
            </div>
            <div class="field">
                <label>Nama File Lure Decoy (Basis Nama)</label>
                <input type="text" id="fileInput" value="Confidential_Enterprise_Access" oninput="updateSnippet()">
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin-top: 15px;">
                <button class="btn" onclick="downloadLure()">HTML (.html)</button>
                <button class="btn" onclick="downloadDOCX()" style="background: #2563eb; color: #fff;">Word (.docx)</button>
                <button class="btn" onclick="downloadXLSX()" style="background: #16a34a; color: #fff;">Excel (.xlsx)</button>
                <button class="btn" onclick="downloadPDF()" style="background: #dc2626; color: #fff;">PDF (.pdf)</button>
                <button class="btn" onclick="downloadURL()" style="background: #d97706; color: #fff;">Shortcut (.url)</button>
            </div>
        </div>

        <div class="card">
            <h2>2. URL Beacon / Tracking Pixel (Tingkat 1)</h2>
            <p style="color: var(--muted); font-size: 13px;">Gunakan link ini untuk disisipkan ke dokumen Word, Excel, PDF, Web bug, atau Markdown:</p>
            <div class="code-box" id="urlBox"></div>
        </div>

        <div class="card">
            <h2>3. Mekanisme Zero-Macro Dual-Beacon</h2>
            <ul>
                <li><strong>Microsoft Word (.docx):</strong> Menyisipkan dua relasi <code>word/_rels/document.xml.rels</code> (Primary + LAN). Tanpa macro, software Word langsung menembakkan kedua beacon!</li>
                <li><strong>Microsoft Excel (.xlsx):</strong> Menyisipkan dua relasi di <code>xl/drawings/_rels/drawing1.xml.rels</code>. Sel tersembunyi memicu HTTP GET ke kedua target.</li>
                <li><strong>Adobe PDF (.pdf):</strong> Menggunakan <code>/OpenAction</code> berantai (<code>/Next</code>). Dokumen memicu koneksi verifikasi jaringan ke kedua endpoint.</li>
                <li><strong>Windows Internet Shortcut (.url):</strong> Menggunakan <code>IconFile</code> tracker untuk memicu sinyal seketika file dibuka di Windows Explorer.</li>
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
        }

        function downloadLure() {
            const token = encodeURIComponent(document.getElementById('tokenInput').value);
            let file = document.getElementById('fileInput').value.replace(/\.[^/.]+$/, "") + ".html";
            const baseUrl = document.getElementById('baseUrlInput').value.replace(/\/+$/, '');
            window.location.href = baseUrl + "/lure/download/html?token=" + token + "&file=" + encodeURIComponent(file) + "&base_url=" + encodeURIComponent(baseUrl);
        }

        function downloadDOCX() {
            const token = encodeURIComponent(document.getElementById('tokenInput').value);
            let file = document.getElementById('fileInput').value.replace(/\.[^/.]+$/, "") + ".docx";
            const baseUrl = document.getElementById('baseUrlInput').value.replace(/\/+$/, '');
            window.location.href = baseUrl + "/lure/download/docx?token=" + token + "&file=" + encodeURIComponent(file) + "&base_url=" + encodeURIComponent(baseUrl);
        }

        function downloadXLSX() {
            const token = encodeURIComponent(document.getElementById('tokenInput').value);
            let file = document.getElementById('fileInput').value.replace(/\.[^/.]+$/, "") + ".xlsx";
            const baseUrl = document.getElementById('baseUrlInput').value.replace(/\/+$/, '');
            window.location.href = baseUrl + "/lure/download/xlsx?token=" + token + "&file=" + encodeURIComponent(file) + "&base_url=" + encodeURIComponent(baseUrl);
        }

        function downloadPDF() {
            const token = encodeURIComponent(document.getElementById('tokenInput').value);
            let file = document.getElementById('fileInput').value.replace(/\.[^/.]+$/, "") + ".pdf";
            const baseUrl = document.getElementById('baseUrlInput').value.replace(/\/+$/, '');
            window.location.href = baseUrl + "/lure/download/pdf?token=" + token + "&file=" + encodeURIComponent(file) + "&base_url=" + encodeURIComponent(baseUrl);
        }

        function downloadURL() {
            const token = encodeURIComponent(document.getElementById('tokenInput').value);
            let file = document.getElementById('fileInput').value.replace(/\.[^/.]+$/, "") + ".url";
            const baseUrl = document.getElementById('baseUrlInput').value.replace(/\/+$/, '');
            window.location.href = baseUrl + "/lure/download/url?token=" + token + "&file=" + encodeURIComponent(file) + "&base_url=" + encodeURIComponent(baseUrl);
        }

        updateSnippet();
    </script>
</body>
</html>`
