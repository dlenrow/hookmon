// Package proccache remembers, for a short time, who each recently exec'd
// process was, from the kernel's exec records.
//
// The fanotify sensors (linker_config, lib_integrity) learn only a PID from
// the kernel and read the rest from /proc/<pid>. A short-lived writer (cp,
// sed -i, mv) can exit before that read. The elf_rpath sensor receives a
// sched_process_exec record for every successful exec on the host, with the
// process's PID, parent, real UID and GID, comm and the filename passed to
// exec. It stores each one here, so the file sensors can still name a writer
// that has exited, and walk its ancestry past parents that have exited.
//
// Only processes that exec'd while elf_rpath was running are known. A process
// that never exec'd during that time (a forked subshell, a daemon started
// before the bus) and has exited is not in the cache.
package proccache

import (
	"container/list"
	"slices"
	"sync"
	"time"
)

const (
	// DefaultMaxEntries bounds the cache. Each entry is a few hundred bytes
	// at most (comm and a filename of up to 255 bytes), so the cache stays
	// under a few MB. Past the bound the oldest exec is evicted, so on a host
	// exec'ing faster than DefaultMaxEntries per DefaultTTL, entries live
	// for less than DefaultTTL.
	DefaultMaxEntries = 16384
	// DefaultTTL is how long an exec is remembered. A file event is read
	// within milliseconds of the write, so the TTL only needs to outlast the
	// writer and its ancestors between their exec and the write; a minute
	// covers a package manager's maintainer scripts. It is kept short so a
	// PID reused after it expires is not mistaken for the old process.
	DefaultTTL = 60 * time.Second
)

// Entry is what the kernel reported about one exec.
type Entry struct {
	PID  uint32
	PPID uint32 // the parent at exec time, before any reparenting
	UID  uint32 // real UID and GID, as /proc/<pid>/status lists first
	GID  uint32
	Comm string // the task's comm after the exec
	// Exe is the filename passed to exec: absolute when the caller gave an
	// absolute path, and for a script it names the script, not the
	// interpreter the kernel loaded.
	Exe string
	// ExecTime is when the bus received the exec record.
	ExecTime time.Time
}

// Cache maps a PID to its most recent exec. It is safe for concurrent use.
type Cache struct {
	max int
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	byPID   map[uint32]*list.Element // of Entry
	order   *list.List               // oldest exec at the front
	waiters map[uint32][]chan struct{}
	feeders int
}

// New returns an empty cache holding up to max entries for ttl each.
func New(max int, ttl time.Duration) *Cache {
	if max < 1 {
		max = 1
	}
	return &Cache{
		max:     max,
		ttl:     ttl,
		now:     time.Now,
		byPID:   make(map[uint32]*list.Element),
		order:   list.New(),
		waiters: make(map[uint32][]chan struct{}),
	}
}

// Default is the cache the elf_rpath sensor fills and the file sensors read.
// The bus constructs its sensors without parameters and runs one elf_rpath
// sensor per process, so one shared instance is the simplest wiring; tests
// use their own instance from New.
var Default = New(DefaultMaxEntries, DefaultTTL)

// SetClock replaces the clock used for ExecTime and expiry (for tests).
func (c *Cache) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// AddFeeder records that a source of exec records is running, and
// RemoveFeeder that one stopped. Wait only waits while one is running:
// without one (elf_rpath disabled or failed to start) nothing will arrive.
func (c *Cache) AddFeeder() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.feeders++
}

// RemoveFeeder undoes one AddFeeder.
func (c *Cache) RemoveFeeder() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.feeders > 0 {
		c.feeders--
	}
}

// Put records an exec, stamping ExecTime. A PID that execs again replaces
// its earlier entry. Expired entries, then the oldest ones past the bound,
// are evicted. Callers waiting for this PID are woken.
func (c *Cache) Put(e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e.ExecTime = now
	if el, ok := c.byPID[e.PID]; ok {
		el.Value = e
		c.order.MoveToBack(el)
	} else {
		c.byPID[e.PID] = c.order.PushBack(e)
	}
	// The list is in ExecTime order, so expired entries are at the front.
	for front := c.order.Front(); front != nil; front = c.order.Front() {
		old := front.Value.(Entry)
		if c.order.Len() <= c.max && now.Sub(old.ExecTime) <= c.ttl {
			break
		}
		c.order.Remove(front)
		delete(c.byPID, old.PID)
	}
	if ws, ok := c.waiters[e.PID]; ok {
		for _, ch := range ws {
			close(ch)
		}
		delete(c.waiters, e.PID)
	}
}

// Get returns the most recent exec of pid, if it is within the TTL.
func (c *Cache) Get(pid uint32) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getLocked(pid)
}

func (c *Cache) getLocked(pid uint32) (Entry, bool) {
	el, ok := c.byPID[pid]
	if !ok {
		return Entry{}, false
	}
	e := el.Value.(Entry)
	if c.now().Sub(e.ExecTime) > c.ttl {
		return Entry{}, false
	}
	return e, true
}

// Wait is Get, except that on a miss it waits up to timeout for an exec of
// pid to be recorded. The exec record and the event that asks about the
// process arrive through separate goroutines, so the record may land a moment
// after the question. Wait returns at once if no feeder is running.
func (c *Cache) Wait(pid uint32, timeout time.Duration) (Entry, bool) {
	c.mu.Lock()
	if e, ok := c.getLocked(pid); ok || c.feeders == 0 || timeout <= 0 {
		c.mu.Unlock()
		return e, ok
	}
	ch := make(chan struct{})
	c.waiters[pid] = append(c.waiters[pid], ch)
	c.mu.Unlock()

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if ws := c.waiters[pid]; ws != nil { // still registered: timed out
		if i := slices.Index(ws, ch); i >= 0 {
			ws = slices.Delete(ws, i, i+1)
		}
		if len(ws) == 0 {
			delete(c.waiters, pid)
		} else {
			c.waiters[pid] = ws
		}
	}
	return c.getLocked(pid)
}

// Len returns the number of entries held, including expired ones not yet
// evicted.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
