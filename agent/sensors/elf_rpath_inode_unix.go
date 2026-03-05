//go:build !windows

package sensors

import (
	"os"
	"syscall"
)

func fileInode(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
