//go:build linux

package enrichment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// enrichHashPath hashes path through the cache.
func enrichHashPath(t *testing.T, c *HashCache, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return c.Hash(f)
}

// enrichOldEnough makes every file look last changed long ago, so the
// cache stores it. The racy-write guard has its own test.
func enrichOldEnough(c *HashCache) {
	c.now = func() time.Time { return time.Now().Add(time.Hour) }
}

func TestEnrichHashCacheHitThenMissOnMtime(t *testing.T) {
	c := NewHashCache(8)
	enrichOldEnough(c)
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("version one"), 0o755); err != nil {
		t.Fatal(err)
	}

	h := enrichHashPath(t, c, path)
	if want := SHA256File(path); h != want || !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("hash = %q, want %q", h, want)
	}
	if c.hits != 0 || c.misses != 1 {
		t.Fatalf("first hash: hits %d misses %d, want 0 and 1", c.hits, c.misses)
	}

	// Unchanged file: a hit.
	if got := enrichHashPath(t, c, path); got != h {
		t.Fatalf("second hash = %q, want %q", got, h)
	}
	if c.hits != 1 || c.misses != 1 {
		t.Fatalf("unchanged file: hits %d misses %d, want 1 and 1", c.hits, c.misses)
	}

	// New mtime: a miss, and the file is hashed again.
	later := time.Now().Add(-time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if got := enrichHashPath(t, c, path); got != h {
		t.Fatalf("hash after touch = %q, want %q", got, h)
	}
	if c.hits != 1 || c.misses != 2 {
		t.Fatalf("after mtime change: hits %d misses %d, want 1 and 2", c.hits, c.misses)
	}
}

// Rewriting a file and putting its mtime back (touch -d, utimensat) does not
// return the old hash: ctime is in the key, and userspace cannot set it.
func TestEnrichHashCacheMtimeRestoredAfterRewrite(t *testing.T) {
	c := NewHashCache(8)
	enrichOldEnough(c)
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("benign!"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	old := enrichHashPath(t, c, path)

	// ctime is kept to the kernel's coarse clock; step past one tick.
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(path, []byte("evil!!!"), 0o755); err != nil { // same size
		t.Fatal(err)
	}
	if err := os.Chtimes(path, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	got := enrichHashPath(t, c, path)
	if got == old {
		t.Fatal("rewritten file with its mtime put back returned the cached hash")
	}
	if want := SHA256File(path); got != want {
		t.Fatalf("hash = %q, want %q", got, want)
	}
}

// A file changed within the last second is hashed but not cached: a second
// write in the same clock tick would leave its key unchanged.
func TestEnrichHashCacheSkipsRecentlyChanged(t *testing.T) {
	c := NewHashCache(8)
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("fresh"), 0o755); err != nil {
		t.Fatal(err)
	}
	enrichHashPath(t, c, path)
	enrichHashPath(t, c, path)
	if c.hits != 0 || c.misses != 2 {
		t.Fatalf("recently changed file: hits %d misses %d, want 0 and 2", c.hits, c.misses)
	}
}

// The cache is an LRU of bounded size.
func TestEnrichHashCacheEvicts(t *testing.T) {
	c := NewHashCache(2)
	enrichOldEnough(c)
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"a", "b", "c"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
		enrichHashPath(t, c, p)
	}
	if n := c.order.Len(); n != 2 {
		t.Fatalf("len = %d, want 2", n)
	}
	enrichHashPath(t, c, paths[0]) // evicted: a miss
	if c.hits != 0 || c.misses != 4 {
		t.Fatalf("hits %d misses %d, want 0 and 4", c.hits, c.misses)
	}
}

// Only regular files are hashed.
func TestEnrichHashCacheRejectsDirectory(t *testing.T) {
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if h := NewHashCache(1).Hash(f); h != "" {
		t.Fatalf("directory hashed as %q", h)
	}
}
