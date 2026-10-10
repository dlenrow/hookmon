//go:build linux

package enrichment

import (
	"os"
	"syscall"
)

// keyOf returns the version key of a file from its stat data.
func keyOf(fi os.FileInfo) (fileKey, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileKey{}, false
	}
	return fileKey{
		dev:     uint64(st.Dev),
		ino:     uint64(st.Ino),
		mtimeNs: st.Mtim.Nano(),
		ctimeNs: st.Ctim.Nano(),
	}, true
}
