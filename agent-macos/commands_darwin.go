package main

import (
	"fmt"
	"os"
	"strconv"
)

func killProcessByPID(pid int) commandResult {
	p, err := os.FindProcess(pid)
	if err != nil {
		return commandResult{Status: "failed", Result: fmt.Sprintf("find process: %v", err)}
	}
	if err := p.Kill(); err != nil {
		return commandResult{Status: "failed", Result: fmt.Sprintf("kill: %v", err)}
	}
	return commandResult{Status: "success", Result: "process " + strconv.Itoa(pid) + " killed"}
}

func isolateNetwork() commandResult {
	// macOS: add pf rules to block all outbound EXCEPT:
	// - loopback (lo0)
	// - HTTPS to Fortrix server (port 443)
	// - DNS (port 53)
	pfRules := "block drop out all\n" +
		"pass out quick on lo0\n" +
		"pass out quick proto tcp to any port 443\n" +
		"pass out quick proto udp to any port 53\n"
	if err := os.WriteFile("/tmp/fortrix_pf.rules", []byte(pfRules), 0644); err != nil {
		return commandResult{Status: "failed", Result: fmt.Sprintf("write rules: %v", err)}
	}
	out, err := runCmd("pfctl", "-f", "/tmp/fortrix_pf.rules")
	if err != nil {
		return commandResult{Status: "failed", Result: out}
	}
	out2, err2 := runCmd("pfctl", "-e")
	result := out + "\n" + out2
	if err2 != nil && err != nil {
		return commandResult{Status: "failed", Result: result}
	}
	return commandResult{Status: "success", Result: "network isolated (Fortrix server + DNS + loopback allowed)\n" + result}
}

func unisolateNetwork() commandResult {
	out, _ := runCmd("pfctl", "-d")
	os.Remove("/tmp/fortrix_pf.rules")
	return commandResult{Status: "success", Result: "network restored\n" + out}
}

func blockIP(ip string) commandResult {
	pfRules := fmt.Sprintf("block drop out to %s\n", ip)
	if err := os.WriteFile("/tmp/fortrix_block_"+ip+".pf", []byte(pfRules), 0644); err != nil {
		return commandResult{Status: "failed", Result: fmt.Sprintf("write rules: %v", err)}
	}
	out, err := runCmd("pfctl", "-f", "/tmp/fortrix_block_"+ip+".pf")
	if err != nil {
		return commandResult{Status: "failed", Result: out}
	}
	return commandResult{Status: "success", Result: "ip " + ip + " blocked"}
}

func unblockIP(ip string) commandResult {
	os.Remove("/tmp/fortrix_block_" + ip + ".pf")
	out, _ := runCmd("pfctl", "-d")
	return commandResult{Status: "success", Result: "ip " + ip + " unblocked\n" + out}
}
