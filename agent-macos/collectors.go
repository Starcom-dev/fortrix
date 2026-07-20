package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// ─── Process Collector ───────────────────────────────────────────────

type procCollector struct {
	mu       sync.Mutex
	seen     map[int32]string // pid -> exe path
	suspDirs []string
	emit     func(Event)
}

func newProcCollector(emit func(Event)) *procCollector {
	return &procCollector{
		seen:     make(map[int32]string),
		suspDirs: suspiciousDirs(),
		emit:     emit,
	}
}

// suspiciousDirs returns common temp/download paths on macOS.
func suspiciousDirs() []string {
	home, _ := os.UserHomeDir()
	return []string{
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Desktop"),
		"/tmp",
		"/var/tmp",
		"/private/tmp",
		"/var/folders", // macOS per-user temp
	}
}

func (pc *procCollector) tick() {
	procs, err := process.Processes()
	if err != nil {
		log.Printf("proc tick: %v", err)
		return
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	current := make(map[int32]string, len(procs))
	for _, p := range procs {
		pid := p.Pid
		name, err := p.Name()
		if err != nil {
			continue
		}
		exe, err := p.Exe()
		if err != nil {
			exe = name
		}
		current[pid] = exe

		if _, known := pc.seen[pid]; !known {
			cmdline, _ := p.Cmdline()
			ppid, _ := p.Ppid()
			susp := isSuspicious(exe, pc.suspDirs)

			pc.emit(Event{
				Type: "proc.new", TS: time.Now().Unix(), Severity: sev(susp, "medium", "low"),
				Data: map[string]any{
					"pid":     pid,
					"ppid":    ppid,
					"name":    name,
					"exe":     exe,
					"cmdline": cmdline,
					"arch":    runtime.GOARCH,
				},
			})
		}
	}
	pc.seen = current
}

func isSuspicious(path string, dirs []string) bool {
	path = filepath.Clean(path)
	for _, d := range dirs {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

func sev(cond bool, ifTrue, ifFalse string) string {
	if cond {
		return ifTrue
	}
	return ifFalse
}

// ─── Network Collector ───────────────────────────────────────────────

type netCollector struct {
	mu   sync.Mutex
	seen map[string]bool // "pid:raddr:port"
	emit func(Event)
}

func newNetCollector(emit func(Event)) *netCollector {
	return &netCollector{
		seen: make(map[string]bool),
		emit: emit,
	}
}

var commonPorts = map[uint32]bool{
	80: true, 443: true, 53: true, 22: true,
	25: true, 465: true, 587: true, 993: true, 143: true,
	123: true, 5223: true, 5228: true, // NTP, Apple push
}

func (nc *netCollector) tick() {
	conns, err := net.Connections("all")
	if err != nil {
		log.Printf("net tick: %v", err)
		return
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()

	current := make(map[string]bool, len(conns))
	for _, c := range conns {
		key := fmt.Sprintf("%d:%s:%d", c.Pid, c.Raddr.IP, c.Raddr.Port)
		current[key] = true

		if _, known := nc.seen[key]; !known {
			// Only flag outbound to remote IPs.
			if c.Status == "ESTABLISHED" && c.Raddr.IP != "" && c.Raddr.IP != "127.0.0.1" && c.Raddr.IP != "::1" {
				public := isPublicIP(c.Raddr.IP)
				uncommon := !commonPorts[c.Raddr.Port]

				nc.emit(Event{
					Type: "net.outbound_new_remote", TS: time.Now().Unix(),
					Severity: sev(public && uncommon, "medium", "low"),
					Data: map[string]any{
						"pid":    c.Pid,
						"raddr":  c.Raddr.IP,
						"port":   c.Raddr.Port,
						"public": public,
					},
				})
			}
		}
	}
	nc.seen = current
}

func isPublicIP(ip string) bool {
	// Simple check: skip private/Loopback/link-local.
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return false
	}
	if strings.HasPrefix(ip, "172.") {
		// 172.16.0.0 – 172.31.255.255
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			if s, err := strconv.Atoi(parts[1]); err == nil && s >= 16 && s <= 31 {
				return false
			}
		}
	}
	if ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" {
		return false
	}
	if strings.HasPrefix(ip, "169.254.") || strings.HasPrefix(ip, "fe80:") {
		return false
	}
	return true
}

// ─── I/O (File Read Burst) Collector ─────────────────────────────────

type ioCollector struct {
	mu       sync.Mutex
	baseline map[int32]*ioSample
	emit     func(Event)
	burstMB  func() float64
}

type ioSample struct {
	readBytes uint64
	time      time.Time
}

func newIOCollector(emit func(Event), burstMB func() float64) *ioCollector {
	return &ioCollector{
		baseline: make(map[int32]*ioSample),
		emit:     emit,
		burstMB:  burstMB,
	}
}

func (ic *ioCollector) tick() {
	procs, err := process.Processes()
	if err != nil {
		log.Printf("io tick: %v", err)
		return
	}

	ic.mu.Lock()
	defer ic.mu.Unlock()

	now := time.Now()
	threshold := ic.burstMB()

	for _, p := range procs {
		pid := p.Pid
		io, err := p.IOCounters()
		if err != nil {
			continue
		}
		prev, ok := ic.baseline[pid]
		if !ok {
			ic.baseline[pid] = &ioSample{readBytes: io.ReadBytes, time: now}
			continue
		}
		if io.ReadBytes <= prev.readBytes {
			// Process restarted or counter wrapped.
			ic.baseline[pid] = &ioSample{readBytes: io.ReadBytes, time: now}
			continue
		}

		delta := io.ReadBytes - prev.readBytes
		elapsed := now.Sub(prev.time).Seconds()
		if elapsed <= 0 {
			elapsed = 1
		}
		readMB := float64(delta) / (1024 * 1024)

		if readMB >= threshold {
			name, _ := p.Name()
			ic.emit(Event{
				Type: "fs.read_burst", TS: now.Unix(), Severity: "high",
				Data: map[string]any{
					"pid":       pid,
					"proc":      name,
					"read_mb":   readMB,
					"window_s":  int(elapsed),
					"threshold": threshold,
				},
			})
		}

		ic.baseline[pid] = &ioSample{readBytes: io.ReadBytes, time: now}
	}

	// Purge stale entries older than 5 minutes.
	for pid, s := range ic.baseline {
		if now.Sub(s.time) > 5*time.Minute {
			delete(ic.baseline, pid)
		}
	}
}

// ─── Signed Binary Check (macOS) ─────────────────────────────────────

// Gatekeeper / code-signing: "spctl" or "codesign" fallback.
// Called by proc collector when suspicious path is detected.

type signCache struct {
	mu   sync.RWMutex
	hash map[string]bool // path hash -> isSigned
}

var signerCache = &signCache{hash: make(map[string]bool)}

func (sc *signCache) isSigned(path string) bool {
	h := fmt.Sprintf("%x", sha256.Sum256([]byte(path)))
	sc.mu.RLock()
	v, ok := sc.hash[h]
	sc.mu.RUnlock()
	if ok {
		return v
	}

	signed := checkCodeSign(path)

	sc.mu.Lock()
	sc.hash[h] = signed
	sc.mu.Unlock()
	return signed
}

func checkCodeSign(path string) bool {
	// Prefer spctl (Gatekeeper assessment), fallback to codesign.
	if out, err := exec.Command("spctl", "--assess", "--verbose", path).CombinedOutput(); err == nil {
		return strings.Contains(string(out), "accepted")
	}
	if out, err := exec.Command("codesign", "--verify", "--verbose", path).CombinedOutput(); err == nil {
		return strings.Contains(string(out), "valid")
	}
	return false
}
