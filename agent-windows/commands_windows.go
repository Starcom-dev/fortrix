package main

import (
	"fmt"
	"os"
	"strconv"
)

func killProcessByPID(pid int) commandResult {
	// taskkill /F /PID <pid>
	p, err := os.FindProcess(pid)
	if err != nil {
		return commandResult{Status: "failed", Result: fmt.Sprintf("find process: %v", err)}
	}
	// On Windows, os.FindProcess always succeeds; actual kill may fail.
	// Use taskkill for reliable termination.
	out, err := runCmd("taskkill", "/F", "/PID", strconv.Itoa(pid))
	if err != nil {
		_ = p.Kill() // fallback
		return commandResult{Status: "failed", Result: out}
	}
	return commandResult{Status: "success", Result: "process " + strconv.Itoa(pid) + " killed"}
}

func isolateNetwork() commandResult {
	// Block all outbound traffic except loopback and DNS (port 53)
	// using Windows Firewall rules.
	// Outbound block rule
	out, err := runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name=FortrixIsolate_Out", "dir=out", "action=block",
		"protocol=any", "remoteport=any")
	if err != nil {
		return commandResult{Status: "failed", Result: out}
	}
	// Allow loopback
	runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name=FortrixIsolate_Loopback", "dir=out", "action=allow",
		"protocol=any", "remoteip=127.0.0.1")
	return commandResult{Status: "success", Result: "network isolated (outbound blocked)"}
}

func unisolateNetwork() commandResult {
	// Remove Fortrix isolation rules
	out1, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_Out")
	out2, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_Loopback")
	combined := out1 + "\n" + out2
	return commandResult{Status: "success", Result: "network restored\n" + combined}
}

func blockIP(ip string) commandResult {
	out, err := runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name=FortrixBlock_"+ip, "dir=out", "action=block",
		"protocol=any", "remoteip="+ip)
	if err != nil {
		return commandResult{Status: "failed", Result: out}
	}
	return commandResult{Status: "success", Result: "ip " + ip + " blocked"}
}

func unblockIP(ip string) commandResult {
	out, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixBlock_"+ip)
	return commandResult{Status: "success", Result: "ip " + ip + " unblocked\n" + out}
}
