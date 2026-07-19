//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procMoveFileExW  = kernel32.NewProc("MoveFileExW")
)

const moveFileReplaceExisting = 0x1

// moveFileWindows atomically replaces dst with src.
// Uses MoveFileExW with MOVEFILE_REPLACE_EXISTING which schedules
// the replacement on next reboot if the file is locked. For our
// use case (agent replacing its own binary while running), this
// typically succeeds since the SCM holds a handle but the file
// itself can be renamed.
func moveFileWindows(src, dst string) error {
	srcW, err := syscall.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	dstW, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	ret, _, errno := procMoveFileExW.Call(
		uintptr(unsafe.Pointer(srcW)),
		uintptr(unsafe.Pointer(dstW)),
		moveFileReplaceExisting,
	)
	if ret == 0 {
		return errno
	}
	return nil
}
