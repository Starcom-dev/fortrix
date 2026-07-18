//go:build windows

package main

import (
	"time"

	"golang.org/x/sys/windows"
)

var (
	user32                        = windows.NewLazySystemDLL("user32.dll")
	procGetClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")
)

func clipboardSequence() uint32 {
	r, _, _ := procGetClipboardSequenceNumber.Call()
	return uint32(r)
}

// clipboardCollector counts clipboard changes per rolling minute.
type clipboardCollector struct {
	lastSeq    uint32
	changes    int
	windowFrom time.Time
	emit       func(Event)
	perMin     func() int
}

func newClipboardCollector(emit func(Event), perMin func() int) *clipboardCollector {
	return &clipboardCollector{
		lastSeq:    clipboardSequence(),
		windowFrom: time.Now(),
		emit:       emit,
		perMin:     perMin,
	}
}

// tick is called every ~2s.
func (cc *clipboardCollector) tick() {
	seq := clipboardSequence()
	if seq != cc.lastSeq {
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
}
