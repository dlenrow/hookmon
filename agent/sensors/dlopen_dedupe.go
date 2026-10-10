package sensors

import (
	"container/list"
	"sync"
	"time"
)

// dlopen_monitor reports a given (executable, library) pair once per
// window. Programs dlopen the same plugins every time they run (an
// interpreter loading its extension modules, a daemon's worker processes),
// so without this one binary floods the event stream with the same fact.
const (
	dlopenDedupeWindow = time.Hour
	dlopenDedupeSize   = 4096
)

type dlopenDedupeKey struct {
	exeHash, libPath string
}

type dlopenDedupeEntry struct {
	key      dlopenDedupeKey
	reported time.Time
}

// dlopenDedupe is an LRU of the (exe hash, library path) pairs reported in
// the last window. The key is the executable's content hash, not its PID, so
// every process running the same binary shares one entry, and the library
// path exactly as passed to dlopen.
type dlopenDedupe struct {
	mu      sync.Mutex
	window  time.Duration
	size    int
	order   *list.List // front is most recently seen; values are *dlopenDedupeEntry
	entries map[dlopenDedupeKey]*list.Element
	now     func() time.Time
}

func newDlopenDedupe(window time.Duration, size int) *dlopenDedupe {
	if size < 1 {
		size = 1
	}
	return &dlopenDedupe{
		window:  window,
		size:    size,
		order:   list.New(),
		entries: make(map[dlopenDedupeKey]*list.Element, size),
		now:     time.Now,
	}
}

// report says whether an event for this pair should be sent: true the first
// time, then false until window has passed since the last one sent. A repeat
// that is dropped does not extend the window. Without an exe hash (the
// process exited before the bus read /proc/<pid>/exe) the pair cannot be
// told apart from other binaries, so the event is always sent.
func (d *dlopenDedupe) report(exeHash, libPath string) bool {
	if exeHash == "" {
		return true
	}
	key := dlopenDedupeKey{exeHash: exeHash, libPath: libPath}
	now := d.now()

	d.mu.Lock()
	defer d.mu.Unlock()
	if el, ok := d.entries[key]; ok {
		e := el.Value.(*dlopenDedupeEntry)
		d.order.MoveToFront(el)
		if now.Sub(e.reported) < d.window {
			return false
		}
		e.reported = now
		return true
	}
	if d.order.Len() >= d.size {
		oldest := d.order.Back()
		d.order.Remove(oldest)
		delete(d.entries, oldest.Value.(*dlopenDedupeEntry).key)
	}
	d.entries[key] = d.order.PushFront(&dlopenDedupeEntry{key: key, reported: now})
	return true
}
