package main

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

// Command is a pending instruction from the server.
type Command struct {
	ID          int64  `json:"id"`
	CommandType string `json:"command_type"`
	Payload     map[string]any `json:"payload"`
}

type commandResult struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

// pollCommands polls /api/v1/commands/pending every 5s and executes any pending commands.
func pollCommands(api *apiClient) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			processPendingCommands(api)
		case <-done:
			return
		}
	}
}

func processPendingCommands(api *apiClient) {
	var cmds []Command
	if err := api.get("/api/v1/commands/pending", &cmds); err != nil {
		return // server unreachable, try again later
	}
	for _, cmd := range cmds {
		result := executeCommand(cmd)
		if err := api.reportCommandResult(cmd.ID, result); err != nil {
			log.Printf("commands: report result failed for #%d: %v", cmd.ID, err)
		}
	}
}

// executeCommand runs the command and returns the result.
func executeCommand(cmd Command) commandResult {
	switch cmd.CommandType {
	case "kill_process":
		return cmdKillProcess(cmd.Payload)
	case "isolate":
		return cmdIsolate(cmd.Payload)
	case "unisolate":
		return cmdUnisolate(cmd.Payload)
	case "block_ip":
		return cmdBlockIP(cmd.Payload)
	case "unblock_ip":
		return cmdUnblockIP(cmd.Payload)
	case "run_scan":
		return cmdRunScan(cmd.Payload)
	default:
		return commandResult{Status: "failed", Result: "unknown command: " + cmd.CommandType}
	}
}

// --------------- Platform-independent helpers ---------------

func getPID(payload map[string]any) (int, error) {
	pid, ok := payload["pid"]
	if !ok {
		return 0, fmt.Errorf("missing pid")
	}
	switch v := pid.(type) {
	case float64:
		return int(v), nil
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("invalid pid: %v", v)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("invalid pid type")
	}
}

// --------------- Default implementations (overridden per-platform) ---------------

func cmdKillProcess(payload map[string]any) commandResult {
	pid, err := getPID(payload)
	if err != nil {
		return commandResult{Status: "failed", Result: err.Error()}
	}
	return killProcessByPID(pid)
}

func cmdIsolate(payload map[string]any) commandResult {
	return isolateNetwork()
}

func cmdUnisolate(payload map[string]any) commandResult {
	return unisolateNetwork()
}

func cmdBlockIP(payload map[string]any) commandResult {
	ip, ok := payload["ip"].(string)
	if !ok || ip == "" {
		return commandResult{Status: "failed", Result: "missing ip"}
	}
	return blockIP(ip)
}

func cmdUnblockIP(payload map[string]any) commandResult {
	ip, ok := payload["ip"].(string)
	if !ok || ip == "" {
		return commandResult{Status: "failed", Result: "missing ip"}
	}
	return unblockIP(ip)
}

func cmdRunScan(payload map[string]any) commandResult {
	// Force immediate collector tick — best-effort.
	// The main loop already runs collectors; this is a no-op signal
	// that the server wants a fresh scan report.
	// In a full implementation, this would trigger all collectors immediately.
	return commandResult{Status: "success", Result: fmt.Sprintf("scan triggered (%s/%s)", runtime.GOOS, runtime.GOARCH)}
}

// runCmd is a helper to execute a shell command and capture output.
func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", string(out), err)
	}
	return string(out), nil
}
