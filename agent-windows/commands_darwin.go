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
	// macOS: add temporary pf rule to block all outbound except loopback
	// Create a temporary anchor
	pfRules := "block drop out all\npass out quick on lo0\n"
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
	return commandResult{Status: "success", Result: "network isolated (pf enabled)\n" + result}
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
