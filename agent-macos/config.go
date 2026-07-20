package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config is persisted alongside the executable.
type Config struct {
	ServerURL   string `json:"server_url"`
	DeviceID    int64  `json:"device_id,omitempty"`
	DeviceToken string `json:"device_token,omitempty"`
}

func configPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	exe, err := os.Executable()
	if err != nil {
		return "fortrix-agent.json"
	}
	return filepath.Join(filepath.Dir(exe), "fortrix-agent.json")
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
