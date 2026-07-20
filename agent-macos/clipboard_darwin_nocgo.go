//go:build darwin && !cgo

package main

import (
	"log"
	"os/exec"
	"time"
)

// clipboardSequence uses osascript to query NSPasteboard changeCount.
// Fallback when CGo is not available (e.g. cross-compile from Windows/Linux).
func clipboardSequence() uint64 {
	// osascript -e 'the clipboard' returns clipboard content; to get changeCount we need
	// to call through AppleScript-ObjC bridge or use a simpler heuristic.
	// Strategy: check if clipboard content changes hash as proxy for change count.
	out, err := exec.Command("osascript", "-e", "get the clipboard").CombinedOutput()
	if err != nil {
		return 0
	}
	// Simple hash of clipboard content.
	var h uint64
	for _, b := range out {
		h = h*31 + uint64(b)
	}
	return h
}

// clipboardCollector counts clipboard changes per rolling minute.
type clipboardCollector struct {
	lastSeq    uint64
	changes    int
	windowFrom time.Time
	emit       func(Event)
	perMin     func() int
}

func newClipboardCollector(emit func(Event), perMin func() int) *clipboardCollector {
	cc := &clipboardCollector{
		windowFrom: time.Now(),
		emit:       emit,
		perMin:     perMin,
	}
	cc.lastSeq = clipboardSequence()
	return cc
}

// tick is called every ~2s.
func (cc *clipboardCollector) tick() {
	seq := clipboardSequence()
	if seq != cc.lastSeq && seq != 0 {
		cc.changes++
		cc.lastSeq = seq
	}
	if time.Since(cc.windowFrom) >= time.Minute {
		if cc.changes >= cc.perMin() {
			cc.emit(Event{
				Type: "clipboard.rapid_changes", TS: time.Now().Unix(), Severity: "medium",
				Data: map[string]any{"count": cc.changes, "window_s": 60},
			})
		}
		cc.changes = 0
		cc.windowFrom = time.Now()
	}

	// Suppress "osascript not found" spam by checking once.
	if seq == 0 {
		cc.windowFrom = time.Now() // reset window to avoid false alerts
	}
}

func init() {
	if _, err := exec.LookPath("osascript"); err != nil {
		log.Println("WARNING: osascript not found — clipboard monitoring disabled")
	}
}
