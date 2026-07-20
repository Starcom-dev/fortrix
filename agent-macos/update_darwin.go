//go:build darwin

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const checkInterval = 4 * time.Hour

// UpdateInfo is the server response for version checks.
type UpdateInfo struct {
	UpdateAvailable bool   `json:"update_available"`
	Current         string `json:"current"`
	Latest          string `json:"latest"`
	URL             string `json:"url"`
	SHA256          string `json:"sha256"`
	ReleaseNotes    string `json:"release_notes"`
}

func checkForUpdate(api *apiClient) {
	var info UpdateInfo
	path := fmt.Sprintf("/api/v1/agent/version?current=%s", agentVersion)
	if err := api.get(path, &info); err != nil {
		log.Printf("check update: %v", err)
		return
	}
	if !info.UpdateAvailable {
		return
	}
	log.Printf("update available: %s → %s", agentVersion, info.Latest)

	// Download
	exe, err := downloadAgent(info.URL)
	if err != nil {
		log.Printf("update download: %v", err)
		return
	}
	defer os.Remove(exe)

	// Verify SHA256
	if info.SHA256 != "" {
		if err := verifySHA256(exe, info.SHA256); err != nil {
			log.Printf("update verify: %v", err)
			return
		}
	}

	// Apply the update.
	if err := applyUpdate(exe); err != nil {
		log.Printf("update apply: %v", err)
		return
	}

	log.Printf("update applied: %s → %s (restarting...)", agentVersion, info.Latest)
	os.Exit(0)
}

func downloadAgent(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	f, err := os.CreateTemp("", "fortrix-agent-update-*")
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.Copy(f, io.LimitReader(resp.Body, 100<<20)); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func verifySHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("sha256 mismatch: want %s, got %s", want, got)
	}
	return nil
}

// applyUpdate replaces the current binary with the new one.
// On macOS we:
// 1. Copy current binary to .old
// 2. Move new binary into place
// 3. chmod +x
// 4. Exit (launchd restarts us if KeepAlive is set)
func applyUpdate(newExe string) error {
	current, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find current exe: %w", err)
	}

	backup := current + ".old"
	os.Remove(backup)

	if err := copyFile(current, backup); err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	os.Chmod(newExe, 0755)

	if err := os.Rename(newExe, current); err != nil {
		os.Remove(backup)
		return fmt.Errorf("replace: %w", err)
	}

	log.Printf("binary replaced; backup at %s", backup)
	return nil
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(d, s)
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func cleanupOldBackup() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	backup := exe + ".old"
	if _, err := os.Stat(backup); err == nil {
		if err := os.Remove(backup); err == nil {
			log.Printf("cleaned up old backup: %s", backup)
		}
	}
}
