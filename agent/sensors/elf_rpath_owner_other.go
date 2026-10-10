//go:build !unix

package sensors

import "os"

// dirOwner reports no owner where there is no Unix stat data.
func dirOwner(string) (uid, gid uint32, perm os.FileMode, ok bool) { return 0, 0, 0, false }
