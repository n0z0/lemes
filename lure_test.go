package main

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestGenerateCanaryDOCX_DualBeacon(t *testing.T) {
	primary := "https://tunnel.example.com/beacon/pixel.png?token=test"
	lan := "http://192.168.1.100:50505/beacon/pixel.png?token=test"
	content := []string{"# TEST TITLE", "Paragraph one", "- Bullet point"}

	data, err := generateCanaryDOCX(primary, lan, content)
	if err != nil {
		t.Fatalf("generateCanaryDOCX failed: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("invalid zip archive: %v", err)
	}

	foundRels := false
	foundDoc := false
	for _, f := range zr.File {
		if f.Name == "word/_rels/document.xml.rels" {
			foundRels = true
			rc, _ := f.Open()
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			rc.Close()
			s := buf.String()
			if !strings.Contains(s, primary) {
				t.Errorf("expected primary beacon in rels")
			}
			if !strings.Contains(s, lan) {
				t.Errorf("expected lan beacon in rels")
			}
		}
		if f.Name == "word/document.xml" {
			foundDoc = true
			rc, _ := f.Open()
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			rc.Close()
			s := buf.String()
			if !strings.Contains(s, "TEST TITLE") {
				t.Errorf("expected title text in document.xml")
			}
			if !strings.Contains(s, "rIdPixel1") || !strings.Contains(s, "rIdPixel2") {
				t.Errorf("expected both rIdPixel1 and rIdPixel2 in document.xml")
			}
		}
	}
	if !foundRels || !foundDoc {
		t.Errorf("expected files missing in docx")
	}
}

func TestGenerateCanaryXLSX_DualBeacon(t *testing.T) {
	primary := "https://tunnel.example.com/beacon/pixel.png?token=test_xlsx"
	lan := "http://192.168.1.100:50505/beacon/pixel.png?token=test_xlsx"
	records := [][]string{
		{"No", "Server", "IP_Address", "Password"},
		{"1", "core-gateway", "10.0.0.1", "admin123"},
	}

	data, err := generateCanaryXLSX(primary, lan, records)
	if err != nil {
		t.Fatalf("generateCanaryXLSX failed: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("invalid zip archive: %v", err)
	}

	foundDrawingRels := false
	foundSheet := false
	for _, f := range zr.File {
		if f.Name == "xl/drawings/_rels/drawing1.xml.rels" {
			foundDrawingRels = true
			rc, _ := f.Open()
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			rc.Close()
			s := buf.String()
			if !strings.Contains(s, primary) || !strings.Contains(s, lan) {
				t.Errorf("expected both beacons in drawing1.xml.rels")
			}
		}
		if f.Name == "xl/worksheets/sheet1.xml" {
			foundSheet = true
			rc, _ := f.Open()
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			rc.Close()
			s := buf.String()
			if !strings.Contains(s, "core-gateway") || !strings.Contains(s, "admin123") {
				t.Errorf("expected tabular content in sheet1.xml")
			}
		}
	}
	if !foundDrawingRels || !foundSheet {
		t.Errorf("expected files missing in xlsx")
	}
}

func TestGenerateCanaryPDF_DualBeacon(t *testing.T) {
	primary := "https://tunnel.example.com/beacon/pixel.png?token=test_pdf"
	lan := "http://192.168.1.100:50505/beacon/pixel.png?token=test_pdf"
	content := []string{"Confidential PDF Report", "Sensitive line"}

	data := generateCanaryPDF(primary, lan, content)
	s := string(data)

	if !strings.HasPrefix(s, "%PDF-1.4") {
		t.Errorf("expected %%PDF-1.4 header")
	}
	if !strings.Contains(s, primary) {
		t.Errorf("expected primary beacon in PDF")
	}
	if !strings.Contains(s, lan) {
		t.Errorf("expected LAN beacon in PDF")
	}
	if !strings.Contains(s, "/Next") {
		t.Errorf("expected /Next action chaining in PDF")
	}
	if !strings.Contains(s, "Confidential PDF Report") {
		t.Errorf("expected content in PDF")
	}
}
