//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework AppKit
#include <stdint.h>

// NSPasteboard changeCount — returns the current change count.
// We call through the Objective-C runtime to avoid needing a .m file.

#include <objc/runtime.h>
#include <objc/message.h>

uint64_t clipboard_change_count(void) {
	id cls = objc_getClass("NSPasteboard");
	id pb = ((id (*)(id, SEL))objc_msgSend)(cls, sel_getUid("generalPasteboard"));
	return ((uint64_t (*)(id, SEL))objc_msgSend)(pb, sel_getUid("changeCount"));
}
*/
import "C"

import (
	"time"
)

func clipboardSequence() uint64 {
	return uint64(C.clipboard_change_count())
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
