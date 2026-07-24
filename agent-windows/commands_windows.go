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
	// Block all outbound TCP traffic using Windows Firewall
	out1, err := runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name=FortrixIsolate_TCP", "dir=out", "action=block",
		"protocol=tcp")
	if err != nil {
		return commandResult{Status: "failed", Result: out1}
	}
	// Block all outbound UDP traffic
	out2, _ := runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name=FortrixIsolate_UDP", "dir=out", "action=block",
		"protocol=udp")
	return commandResult{Status: "success", Result: "network isolated (TCP+UDP outbound blocked)\n" + out1 + "\n" + out2}
}

func unisolateNetwork() commandResult {
	// Remove Fortrix isolation rules
	out1, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_TCP")
	out2, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_UDP")
	out3, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_Out")
	out4, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_Loopback")
	combined := out1 + "\n" + out2 + "\n" + out3 + "\n" + out4
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
