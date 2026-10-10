package enrichment

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"time"
)

// SHA256File computes the SHA256 hash of a file at the given path.
// Returns "sha256:<hex>", or empty string on error.
func SHA256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	return SHA256Reader(f)
}

// SHA256Reader returns "sha256:<hex>" of everything r yields, or "" on a
// read error. Every file hash HookMon reports uses this format.
func SHA256Reader(r io.Reader) string {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return ""
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// hashCacheCap bounds the exe hash cache, one entry per file version.
const hashCacheCap = 4096

// racyWindow: a file whose ctime is less than this before hashing began is
// hashed but not cached. A write that lands in the same clock tick as the
// previous one leaves mtime and ctime unchanged, so the cache could not
// tell the versions apart. Any later write gets a newer tick.
const racyWindow = time.Second

// fileKey identifies one version of a file: device, inode, mtime and ctime.
// Rewriting the file changes mtime and ctime; replacing it changes the
// inode. ctime is in the key because utimensat can put mtime back after a
// rewrite, and nothing in userspace can set ctime.
type fileKey struct {
	dev     uint64
	ino     uint64
	mtimeNs int64
	ctimeNs int64
}

type hashEntry struct {
	key  fileKey
	hash string
}

// HashCache caches file hashes by file version, so a binary is hashed once
// per version rather than on every event. It is an LRU and safe for
// concurrent use.
type HashCache struct {
	mu      sync.Mutex
	max     int
	order   *list.List // front is most recently used; values are *hashEntry
	entries map[fileKey]*list.Element
	now     func() time.Time

	hits, misses uint64
}

// NewHashCache returns a cache holding up to max entries.
func NewHashCache(max int) *HashCache {
	if max < 1 {
		max = 1
	}
	return &HashCache{
		max:     max,
		order:   list.New(),
		entries: make(map[fileKey]*list.Element),
		now:     time.Now,
	}
}

// Hash returns "sha256:<hex>" of the open regular file f, from its start,
// or "" if it cannot be read. A cached hash is used if f's version matches.
func (c *HashCache) Hash(f *os.File) string {
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	key, keyed := keyOf(fi)
	if keyed {
		if h, ok := c.get(key); ok {
			return h
		}
	}
	started := c.now()
	h := SHA256Reader(io.NewSectionReader(f, 0, math.MaxInt64))
	if h == "" || !keyed {
		return h
	}
	// Cache only if the file did not change while it was read, and its last
	// change is old enough that a later one gets a different ctime.
	if fi2, err := f.Stat(); err == nil {
		if key2, ok := keyOf(fi2); ok && key2 == key && started.Sub(time.Unix(0, key.ctimeNs)) >= racyWindow {
			c.put(key, h)
		}
	}
	return h
}

func (c *HashCache) get(key fileKey) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		c.misses++
		return "", false
	}
	c.hits++
	c.order.MoveToFront(el)
	return el.Value.(*hashEntry).hash, true
}

func (c *HashCache) put(key fileKey, hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		el.Value.(*hashEntry).hash = hash
		c.order.MoveToFront(el)
		return
	}
	if c.order.Len() >= c.max {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*hashEntry).key)
	}
	c.entries[key] = c.order.PushFront(&hashEntry{key: key, hash: hash})
}
