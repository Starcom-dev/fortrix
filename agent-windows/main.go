package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

const agentVersion = "0.3.0"

// done is closed by the service wrapper to request shutdown.
var done = make(chan struct{})

var (
	serverFlag   = flag.String("server", "", "server base URL, e.g. https://fortrix.xyz")
	enrollFlag   = flag.String("enroll", "", "enrollment key (first run)")
	configFlag   = flag.String("config", "", "config file path (default: alongside exe)")
	onceFlag     = flag.Bool("once", false, "run one collection cycle then exit (testing)")
	installFlag  = flag.Bool("install", false, "install as Windows service")
	uninstallFlag = flag.Bool("uninstall", false, "uninstall Windows service")
)

// eventQueue is a bounded, thread-safe event buffer.
type eventQueue struct {
	mu     sync.Mutex
	events []Event
}

func (q *eventQueue) push(e Event) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.events) >= 5000 {
		return
	}
	q.events = append(q.events, e)
}

func (q *eventQueue) drain(max int) []Event {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.events) == 0 {
		return nil
	}
	n := len(q.events)
	if n > max {
		n = max
	}
	batch := make([]Event, n)
	copy(batch, q.events[:n])
	q.events = q.events[n:]
	return batch
}

func (q *eventQueue) requeue(events []Event) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events = append(events, q.events...)
	if len(q.events) > 5000 {
		q.events = q.events[:5000]
	}
}

func main() {
	flag.Parse()

	// Running under Windows SCM? Hand control to the service wrapper.
	if maybeRunAsService() {
		return
	}
	if *installFlag {
		if err := installService(); err != nil {
			log.Fatal(err)
		}
		log.Println("Fortrix Agent service installed successfully")
		return
	}
	if *uninstallFlag {
		if err := uninstallService(); err != nil {
			log.Fatal(err)
		}
		log.Println("Fortrix Agent service uninstalled successfully")
		return
	}

	runAgent()
}

func runAgent() {
	cfgPath := configPath(*configFlag)
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *serverFlag != "" {
		cfg.ServerURL = *serverFlag
	}
	if cfg.ServerURL == "" {
		log.Fatal("no server URL; run with -server https://fortrix.xyz -enroll <KEY>")
	}

	// Enroll if we have no token yet.
	if cfg.DeviceToken == "" {
		if *enrollFlag == "" {
			log.Fatal("not enrolled; run with -enroll <KEY>")
		}
		hostname, _ := os.Hostname()
		api := newAPIClient(cfg.ServerURL, "")
		info, _ := host.Info()
		osName := runtime.GOOS
		if info != nil {
			osName = fmt.Sprintf("%s %s", info.Platform, info.PlatformVersion)
		}
		resp, err := api.enroll(*enrollFlag, hostname, osName, runtime.GOARCH, agentVersion)
		if err != nil {
			log.Fatalf("enroll failed: %v", err)
		}
		cfg.DeviceID = resp.DeviceID
		cfg.DeviceToken = resp.DeviceToken
		if err := cfg.save(cfgPath); err != nil {
			log.Fatalf("save config: %v", err)
		}
		log.Printf("enrolled OK as device #%d", cfg.DeviceID)
	}

	api := newAPIClient(cfg.ServerURL, cfg.DeviceToken)

	// Server-driven thresholds (refreshed hourly).
	var cfgMu sync.RWMutex
	agentCfg, _ := api.fetchConfig()
	getBurstMB := func() float64 {
		cfgMu.RLock()
		defer cfgMu.RUnlock()
		return agentCfg.ReadBurstMB
	}
	getClipPerMin := func() int {
		cfgMu.RLock()
		defer cfgMu.RUnlock()
		return agentCfg.ClipboardPerMin
	}

	queue := &eventQueue{}
	emit := func(e Event) { queue.push(e) }

	pc := newProcCollector(emit)
	nc := newNetCollector(emit)
	ic := newIOCollector(emit, getBurstMB)
	cc := newClipboardCollector(emit, getClipPerMin)

	sendHeartbeat := func() {
		cpus, _ := cpu.Percent(time.Second, false)
		cpuPct := 0.0
		if len(cpus) > 0 {
			cpuPct = cpus[0]
		}
		memPct := 0.0
		if vm, err := mem.VirtualMemory(); err == nil {
			memPct = vm.UsedPercent
		}
		uptime, _ := host.Uptime()
		if err := api.heartbeat(cpuPct, memPct, uptime, agentVersion); err != nil {
			log.Printf("heartbeat: %v", err)
		}
	}

	flush := func() {
		for {
			batch := queue.drain(200)
			if batch == nil {
				return
			}
			if err := api.sendEvents(batch); err != nil {
				log.Printf("send events: %v (requeued %d)", err, len(batch))
				queue.requeue(batch)
				return
			}
		}
	}

	if *onceFlag {
		sendHeartbeat()
		// ETW doesn't batch in -once mode well; use polling fallback.
		pc.tick()
		nc.tick()
		ic.tick()
		cc.tick()
		flush()
		log.Println("once: done")
		return
	}

	log.Printf("fortrix-agent %s started (device #%d → %s)", agentVersion, cfg.DeviceID, cfg.ServerURL)

	procT := time.NewTicker(1 * time.Second)   // high-frequency polling for near-realtime detection
	netT := time.NewTicker(20 * time.Second)
	ioT := time.NewTicker(60 * time.Second)
	clipT := time.NewTicker(2 * time.Second)
	hbT := time.NewTicker(60 * time.Second)
	sendT := time.NewTicker(30 * time.Second)
	cfgT := time.NewTicker(1 * time.Hour)
	updateT := time.NewTicker(checkInterval)

	sendHeartbeat()

	for {
		select {
		case <-procT.C:
			pc.tick()
		case <-netT.C:
			nc.tick()
		case <-ioT.C:
			ic.tick()
		case <-clipT.C:
			cc.tick()
		case <-hbT.C:
			sendHeartbeat()
		case <-sendT.C:
			flush()
		case <-cfgT.C:
			if fresh, err := api.fetchConfig(); err == nil {
				cfgMu.Lock()
				agentCfg = fresh
				cfgMu.Unlock()
			}
		case <-updateT.C:
			checkForUpdate(api)
		case <-done:
			log.Println("shutting down...")
			flush()
			return
		}
	}
}
