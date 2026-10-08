package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"time"
)

type TunnelManager struct {
	cmd       *exec.Cmd
	cancel    context.CancelFunc
	PublicURL string
}

// startCloudflareTunnel menjalankan cloudflared Quick Tunnel otomatis untuk mengekspos port lemes ke domain HTTPS publik gratis
func startCloudflareTunnel(localPort string) (*TunnelManager, error) {
	cfBin, err := exec.LookPath("cloudflared")
	if err != nil {
		return nil, fmt.Errorf("binary 'cloudflared' tidak ditemukan di PATH. Pastikan cloudflared sudah terinstal (https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)")
	}

	target := fmt.Sprintf("http://localhost%s", localPort)
	log.Printf("[TUNNEL] Memulai Cloudflare Tunnel ke %s...", target)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, cfBin, "tunnel", "--url", target, "--no-autoupdate")

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("gagal membuat pipe stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("gagal menjalankan cloudflared: %w", err)
	}

	urlChan := make(chan string, 1)
	errChan := make(chan error, 1)

	re := regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		found := false
		for scanner.Scan() {
			line := scanner.Text()
			if !found {
				if match := re.FindString(line); match != "" {
					found = true
					urlChan <- match
				}
			}
		}
		if !found {
			errChan <- fmt.Errorf("cloudflared berhenti tanpa menghasilkan URL Quick Tunnel")
		}
	}()

	select {
	case pubURL := <-urlChan:
		log.Printf("[TUNNEL] ✅ Cloudflare HTTPS Tunnel Aktif: %s", pubURL)
		return &TunnelManager{
			cmd:       cmd,
			cancel:    cancel,
			PublicURL: pubURL,
		}, nil
	case err := <-errChan:
		cancel()
		return nil, err
	case <-time.After(30 * time.Second):
		cancel()
		return nil, fmt.Errorf("timeout menunggu URL Quick Tunnel dari cloudflared (30s)")
	}
}

func (t *TunnelManager) Stop() {
	if t != nil && t.cancel != nil {
		log.Printf("[TUNNEL] Menghentikan Cloudflare Tunnel...")
		t.cancel()
		if t.cmd != nil && t.cmd.Process != nil {
			_ = t.cmd.Process.Kill()
		}
	}
}
