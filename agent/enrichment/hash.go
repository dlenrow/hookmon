package enrichment

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// SHA256File computes the SHA256 hash of a file at the given path.
// Returns the hex-encoded hash string, or empty string on error.
func SHA256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}
