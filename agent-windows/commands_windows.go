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
	// Allow Fortrix server communication BEFORE blocking everything else.
	// This ensures the agent can still receive commands (including unisolate).
	runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name=FortrixIsolate_Allow_Server", "dir=out", "action=allow",
		"protocol=tcp", "remoteport=443")
	runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name=FortrixIsolate_Allow_DNS", "dir=out", "action=allow",
		"protocol=udp", "remoteport=53")
	runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name=FortrixIsolate_Allow_Loopback", "dir=out", "action=allow",
		"remoteip=127.0.0.1")

	// Block all other outbound TCP traffic
	out1, err := runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name=FortrixIsolate_TCP", "dir=out", "action=block",
		"protocol=tcp")
	if err != nil {
		return commandResult{Status: "failed", Result: out1}
	}
	// Block all other outbound UDP traffic
	out2, _ := runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name=FortrixIsolate_UDP", "dir=out", "action=block",
		"protocol=udp")
	return commandResult{Status: "success", Result: "network isolated (Fortrix server + DNS + loopback allowed, all other TCP/UDP blocked)\n" + out1 + "\n" + out2}
}

func unisolateNetwork() commandResult {
	// Remove all Fortrix isolation rules (allow + block)
	out1, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_Allow_Server")
	out2, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_Allow_DNS")
	out3, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_Allow_Loopback")
	out4, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_TCP")
	out5, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_UDP")
	out6, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_Out")
	out7, _ := runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=FortrixIsolate_Loopback")
	combined := out1 + "\n" + out2 + "\n" + out3 + "\n" + out4 + "\n" + out5 + "\n" + out6 + "\n" + out7
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
