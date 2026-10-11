package enrichment

// SHA256File and SHA256Reader, on every platform (fix plan step 7h).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// t7hFailingReader yields some bytes, then an error.
type t7hFailingReader struct{ sent bool }

func (r *t7hFailingReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, "partial"), nil
	}
	return 0, errors.New("t7h: read failed")
}

func TestSHA256_Format(t *testing.T) {
	const helloHash = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got := SHA256Reader(strings.NewReader("hello")); got != helloHash {
		t.Errorf("SHA256Reader(hello) = %q", got)
	}
	if got := SHA256Reader(strings.NewReader("")); got != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty input: %q", got)
	}
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := SHA256File(p); got != helloHash {
		t.Errorf("SHA256File = %q", got)
	}
	// Errors are "", never a hash of what was read so far.
	if got := SHA256File(filepath.Join(t.TempDir(), "missing")); got != "" {
		t.Errorf("missing file: %q", got)
	}
	if got := SHA256Reader(&t7hFailingReader{}); got != "" {
		t.Errorf("failing reader: %q", got)
	}
}
