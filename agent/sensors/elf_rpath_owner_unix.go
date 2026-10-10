//go:build unix

package sensors

import (
	"os"
	"syscall"
)

// dirOwner returns the owner, group and permission bits of the directory
// at path, following symlinks as ld.so does.
func dirOwner(path string) (uid, gid uint32, perm os.FileMode, ok bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return st.Uid, st.Gid, fi.Mode().Perm(), true
}
