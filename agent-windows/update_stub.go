//go:build !windows

package main

import "os"

func moveFileWindows(src, dst string) error {
	return os.Rename(src, dst)
}
