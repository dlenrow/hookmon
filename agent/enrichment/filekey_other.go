//go:build !linux

package enrichment

import "os"

// keyOf reports no key off Linux, so hashes are not cached there. The bus
// runs only on Linux.
func keyOf(os.FileInfo) (fileKey, bool) { return fileKey{}, false }
