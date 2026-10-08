package main

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestGenerateCanaryDOCX(t *testing.T) {
	beaconURL := "http://example.com/beacon/pixel.png?token=test"
	data, err := generateCanaryDOCX(beaconURL)
	if err != nil {
		t.Fatalf("generateCanaryDOCX failed: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("invalid zip archive: %v", err)
	}

	foundRels := false
	for _, f := range zr.File {
		if f.Name == "word/_rels/document.xml.rels" {
			foundRels = true
			rc, _ := f.Open()
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			rc.Close()
			if !strings.Contains(buf.String(), beaconURL) {
				t.Errorf("expected beaconURL in document.xml.rels")
			}
			if !strings.Contains(buf.String(), `TargetMode="External"`) {
				t.Errorf("expected TargetMode=\"External\" in document.xml.rels")
			}
		}
	}
	if !foundRels {
		t.Errorf("word/_rels/document.xml.rels not found in docx")
	}
}

func TestGenerateCanaryXLSX(t *testing.T) {
	beaconURL := "http://example.com/beacon/pixel.png?token=test_xlsx"
	data, err := generateCanaryXLSX(beaconURL)
	if err != nil {
		t.Fatalf("generateCanaryXLSX failed: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("invalid zip archive: %v", err)
	}

	foundDrawingRels := false
	for _, f := range zr.File {
		if f.Name == "xl/drawings/_rels/drawing1.xml.rels" {
			foundDrawingRels = true
			rc, _ := f.Open()
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			rc.Close()
			if !strings.Contains(buf.String(), beaconURL) {
				t.Errorf("expected beaconURL in drawing1.xml.rels")
			}
			if !strings.Contains(buf.String(), `TargetMode="External"`) {
				t.Errorf("expected TargetMode=\"External\" in drawing1.xml.rels")
			}
		}
	}
	if !foundDrawingRels {
		t.Errorf("xl/drawings/_rels/drawing1.xml.rels not found in xlsx")
	}
}

func TestGenerateCanaryPDF(t *testing.T) {
	beaconURL := "http://example.com/beacon/pixel.png?token=test_pdf"
	data := generateCanaryPDF(beaconURL)

	s := string(data)
	if !strings.HasPrefix(s, "%PDF-1.4") {
		t.Errorf("expected %%PDF-1.4 header")
	}
	if !strings.Contains(s, "/OpenAction") {
		t.Errorf("expected /OpenAction in PDF")
	}
	if !strings.Contains(s, beaconURL) {
		t.Errorf("expected beaconURL in PDF")
	}
	if !strings.Contains(s, "%%EOF") {
		t.Errorf("expected %%EOF trailer")
	}
}
