package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---- proc collector: detect new processes ----

type procCollector struct {
	known map[int32]int64 // pid -> createTime
	emit  func(Event)
}

func newProcCollector(emit func(Event)) *procCollector {
	pc := &procCollector{known: map[int32]int64{}, emit: emit}
	// Prime baseline so we don't flood on startup.
	if procs, err := process.Processes(); err == nil {
		for _, p := range procs {
			ct, _ := p.CreateTime()
			pc.known[p.Pid] = ct
		}
	}
	return pc
}

func isSuspiciousPath(exe string) bool {
	low := strings.ToLower(exe)
	return strings.Contains(low, "\\temp\\") ||
		strings.Contains(low, "\\tmp\\") ||
		strings.Contains(low, "\\downloads\\")
}

func (pc *procCollector) tick() {
	procs, err := process.Processes()
	if err != nil {
		return
	}
	current := map[int32]int64{}
	for _, p := range procs {
		ct, _ := p.CreateTime()
		current[p.Pid] = ct
		prev, seen := pc.known[p.Pid]
		if seen && prev == ct {
			continue // same process as before
		}
		name, _ := p.Name()
		exe, _ := p.Exe()
		cmd, _ := p.Cmdline()
		ppid, _ := p.Ppid()
		if name == "" && exe == "" {
			continue // no visibility (system proc)
		}
		susp := isSuspiciousPath(exe)
		sev := "info"
		if susp {
			sev = "medium"
		}
		pc.emit(Event{
			Type: "proc.new", TS: time.Now().Unix(), Severity: sev,
			Data: map[string]any{
				"name": name, "exe": exe, "cmdline": truncate(cmd, 512),
				"pid": p.Pid, "ppid": ppid, "suspicious": susp,
			},
		})
	}
	pc.known = current
}

// ---- net collector: new outbound remotes ----

type netCollector struct {
	seen map[string]bool // "pid|ip"
	emit func(Event)
}

func newNetCollector(emit func(Event)) *netCollector {
	nc := &netCollector{seen: map[string]bool{}, emit: emit}
	// Prime baseline.
	if conns, err := gnet.Connections("tcp"); err == nil {
		for _, c := range conns {
			if c.Status == "ESTABLISHED" && c.Raddr.IP != "" {
				nc.seen[connKey(c.Pid, c.Raddr.IP)] = true
			}
		}
	}
	return nc
}

func connKey(pid int32, ip string) string {
	return fmt.Sprintf("%d|%s", pid, ip)
}

func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified())
}

func (nc *netCollector) tick() {
	conns, err := gnet.Connections("tcp")
	if err != nil {
		return
	}
	procNames := map[int32]string{}
	for _, c := range conns {
		if c.Status != "ESTABLISHED" || c.Raddr.IP == "" || c.Pid == 0 {
			continue
		}
		k := connKey(c.Pid, c.Raddr.IP)
		if nc.seen[k] {
			continue
		}
		nc.seen[k] = true
		name, ok := procNames[c.Pid]
		if !ok {
			if p, err := process.NewProcess(c.Pid); err == nil {
				name, _ = p.Name()
			}
			procNames[c.Pid] = name
		}
		public := isPublicIP(c.Raddr.IP)
		sev := "info"
		if public && c.Raddr.Port != 80 && c.Raddr.Port != 443 {
			sev = "low"
		}
		nc.emit(Event{
			Type: "net.outbound_new_remote", TS: time.Now().Unix(), Severity: sev,
			Data: map[string]any{
				"proc": name, "pid": c.Pid, "raddr": c.Raddr.IP,
				"port": c.Raddr.Port, "public": public,
			},
		})
	}
	// Bound memory: reset baseline if it grows too large.
	if len(nc.seen) > 20000 {
		nc.seen = map[string]bool{}
	}
}

// ---- io collector: burst file reads ----

type ioCollector struct {
	lastRead map[int32]uint64 // pid -> cumulative read bytes
	emit     func(Event)
	burstMB  func() float64
}

func newIOCollector(emit func(Event), burstMB func() float64) *ioCollector {
	ic := &ioCollector{lastRead: map[int32]uint64{}, emit: emit, burstMB: burstMB}
	ic.prime()
	return ic
}

func (ic *ioCollector) prime() {
	out := map[int32]uint64{}
	procs, err := process.Processes()
	if err != nil {
		return
	}
	for _, p := range procs {
		io, err := p.IOCounters()
		if err != nil || io == nil {
			continue
		}
		out[p.Pid] = io.ReadBytes
	}
	ic.lastRead = out
}

func (ic *ioCollector) tick() {
	prev := ic.lastRead
	procs, err := process.Processes()
	if err != nil {
		return
	}
	current := map[int32]uint64{}
	threshold := ic.burstMB() * 1024 * 1024
	for _, p := range procs {
		io, err := p.IOCounters()
		if err != nil || io == nil {
			continue
		}
		current[p.Pid] = io.ReadBytes
		before, seen := prev[p.Pid]
		if !seen || io.ReadBytes < before {
			continue
		}
		delta := float64(io.ReadBytes - before)
		if delta >= threshold {
			name, _ := p.Name()
			exe, _ := p.Exe()
			ic.emit(Event{
				Type: "fs.read_burst", TS: time.Now().Unix(), Severity: "high",
				Data: map[string]any{
					"proc": name, "exe": exe, "pid": p.Pid,
					"read_mb": delta / 1024 / 1024,
				},
			})
		}
	}
	ic.lastRead = current
}
