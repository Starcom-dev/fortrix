package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Event is a single telemetry event sent to the server.
type Event struct {
	Type     string         `json:"type"`
	TS       int64          `json:"ts"`
	Severity string         `json:"severity"`
	Data     map[string]any `json:"data"`
}

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newAPIClient(baseURL, token string) *apiClient {
	return &apiClient{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *apiClient) post(path string, payload any, out any) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", a.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (a *apiClient) get(path string, out any) error {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	return json.Unmarshal(b, out)
}

type enrollResp struct {
	DeviceID    int64  `json:"device_id"`
	DeviceToken string `json:"device_token"`
}

func (a *apiClient) enroll(key, hostname, osName, arch, version string) (*enrollResp, error) {
	var out enrollResp
	_, err := a.post("/api/v1/enroll", map[string]any{
		"enroll_key":    key,
		"hostname":      hostname,
		"os":            osName,
		"arch":          arch,
		"agent_version": version,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *apiClient) heartbeat(cpuPct, memPct float64, uptimeS uint64, version string) error {
	_, err := a.post("/api/v1/heartbeat", map[string]any{
		"cpu_pct":       cpuPct,
		"mem_pct":       memPct,
		"uptime_s":      uptimeS,
		"agent_version": version,
	}, nil)
	return err
}

func (a *apiClient) sendEvents(events []Event) error {
	_, err := a.post("/api/v1/events", map[string]any{"events": events}, nil)
	return err
}

// --------------- Remote Commands ---------------

func (a *apiClient) reportCommandResult(cmdID int64, result commandResult) error {
	_, err := a.post(fmt.Sprintf("/api/v1/commands/%d/result", cmdID), result, nil)
	return err
}

// AgentConfig holds server-driven thresholds.
type AgentConfig struct {
	ReadBurstMB     float64 `json:"read_burst_mb"`
	ClipboardPerMin int     `json:"clipboard_per_min"`
}

func (a *apiClient) fetchConfig() (*AgentConfig, error) {
	cfg := &AgentConfig{ReadBurstMB: 500, ClipboardPerMin: 30}
	if err := a.get("/api/v1/config", cfg); err != nil {
		return cfg, err
	}
	if cfg.ReadBurstMB <= 0 {
		cfg.ReadBurstMB = 500
	}
	if cfg.ClipboardPerMin <= 0 {
		cfg.ClipboardPerMin = 30
	}
	return cfg, nil
}
