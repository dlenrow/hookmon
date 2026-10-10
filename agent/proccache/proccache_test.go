package proccache

import (
	"sync"
	"testing"
	"time"
)

// pcacheClock is a settable clock for expiry tests.
type pcacheClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *pcacheClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *pcacheClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func pcacheNew(max int, ttl time.Duration) (*Cache, *pcacheClock) {
	clk := &pcacheClock{t: time.Unix(1000, 0)}
	c := New(max, ttl)
	c.SetClock(clk.now)
	return c, clk
}

func TestPcacheGetAndTTL(t *testing.T) {
	c, clk := pcacheNew(16, time.Minute)
	c.Put(Entry{PID: 42, PPID: 7, UID: 1000, GID: 1001, Comm: "cp", Exe: "/usr/bin/cp"})

	e, ok := c.Get(42)
	if !ok || e.PID != 42 || e.PPID != 7 || e.UID != 1000 || e.GID != 1001 || e.Comm != "cp" || e.Exe != "/usr/bin/cp" {
		t.Fatalf("Get(42) = %+v, %v", e, ok)
	}
	if !e.ExecTime.Equal(time.Unix(1000, 0)) {
		t.Errorf("ExecTime = %v, want the clock at Put", e.ExecTime)
	}
	if _, ok := c.Get(43); ok {
		t.Error("Get of a PID never put succeeded")
	}

	clk.add(time.Minute) // exactly the TTL: still valid
	if _, ok := c.Get(42); !ok {
		t.Error("entry gone at exactly the TTL")
	}
	clk.add(time.Nanosecond)
	if e, ok := c.Get(42); ok {
		t.Errorf("entry past the TTL returned: %+v", e)
	}

	// The next Put evicts the expired entry.
	c.Put(Entry{PID: 50})
	if n := c.Len(); n != 1 {
		t.Errorf("Len after expiry = %d, want 1", n)
	}
}

func TestPcacheBoundEvictsOldest(t *testing.T) {
	c, clk := pcacheNew(3, time.Hour)
	for pid := uint32(1); pid <= 5; pid++ {
		c.Put(Entry{PID: pid})
		clk.add(time.Second)
	}
	if n := c.Len(); n != 3 {
		t.Fatalf("Len = %d, want the bound 3", n)
	}
	for pid := uint32(1); pid <= 5; pid++ {
		_, ok := c.Get(pid)
		if want := pid >= 3; ok != want {
			t.Errorf("Get(%d) present=%v, want %v", pid, ok, want)
		}
	}
}

func TestPcacheOverwriteOnReExec(t *testing.T) {
	c, clk := pcacheNew(2, time.Hour)
	c.Put(Entry{PID: 10, PPID: 1, Comm: "sh", Exe: "/bin/sh"})
	clk.add(time.Second)
	c.Put(Entry{PID: 20, Comm: "other"})
	clk.add(time.Second)
	// PID 10 execs cp: its entry is replaced and becomes the newest.
	c.Put(Entry{PID: 10, PPID: 1, Comm: "cp", Exe: "/usr/bin/cp"})

	e, ok := c.Get(10)
	if !ok || e.Comm != "cp" || e.Exe != "/usr/bin/cp" || !e.ExecTime.Equal(time.Unix(1002, 0)) {
		t.Fatalf("after re-exec Get(10) = %+v, %v", e, ok)
	}
	if n := c.Len(); n != 2 {
		t.Fatalf("Len = %d, want 2 (one entry per PID)", n)
	}
	// Past the bound, the oldest exec (PID 20) goes, not the re-exec'd PID.
	c.Put(Entry{PID: 30})
	if _, ok := c.Get(20); ok {
		t.Error("PID 20, the oldest exec, was not evicted")
	}
	if e, ok := c.Get(10); !ok || e.Comm != "cp" {
		t.Errorf("re-exec'd PID 10 evicted or wrong: %+v, %v", e, ok)
	}
}

func TestPcacheWaitLateInsert(t *testing.T) {
	c := New(16, time.Minute)
	c.AddFeeder()
	go func() {
		time.Sleep(50 * time.Millisecond)
		c.Put(Entry{PID: 99, UID: 0, Comm: "sed"})
	}()
	start := time.Now()
	e, ok := c.Wait(99, 5*time.Second)
	if !ok || e.Comm != "sed" {
		t.Fatalf("Wait(99) = %+v, %v; want the late entry", e, ok)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Wait returned after %v; it should wake on the Put", d)
	}
	if n := pcacheWaiters(c); n != 0 {
		t.Errorf("%d waiters left registered", n)
	}
}

func TestPcacheWaitTimeout(t *testing.T) {
	c := New(16, time.Minute)
	c.AddFeeder()
	c.Put(Entry{PID: 1}) // a different PID does not wake the waiter
	start := time.Now()
	if e, ok := c.Wait(77, 100*time.Millisecond); ok {
		t.Fatalf("Wait for a PID never put returned %+v", e)
	}
	if d := time.Since(start); d < 100*time.Millisecond {
		t.Errorf("Wait gave up after %v, before the timeout", d)
	}
	if n := pcacheWaiters(c); n != 0 {
		t.Errorf("%d waiters left registered after the timeout", n)
	}
	// A record arriving after the timeout is still found by Get.
	c.Put(Entry{PID: 77})
	if _, ok := c.Get(77); !ok {
		t.Error("entry put after the timeout not found")
	}
}

func TestPcacheWaitWithoutFeederReturnsAtOnce(t *testing.T) {
	c := New(16, time.Minute)
	start := time.Now()
	if _, ok := c.Wait(5, 5*time.Second); ok {
		t.Fatal("Wait on an empty cache succeeded")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Wait without a feeder took %v; nothing can arrive, so it should not wait", d)
	}

	c.AddFeeder()
	c.RemoveFeeder()
	c.RemoveFeeder() // extra removes do not go negative
	start = time.Now()
	c.Wait(5, 5*time.Second)
	if d := time.Since(start); d > time.Second {
		t.Errorf("Wait after the feeder stopped took %v", d)
	}
}

func TestPcacheWaitHitAndManyWaiters(t *testing.T) {
	c := New(16, time.Minute)
	c.AddFeeder()
	c.Put(Entry{PID: 3, Comm: "x"})
	if e, ok := c.Wait(3, time.Hour); !ok || e.Comm != "x" {
		t.Fatalf("Wait on a cached PID = %+v, %v", e, ok)
	}

	const n = 8
	var wg sync.WaitGroup
	got := make(chan bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok := c.Wait(4, 5*time.Second)
			got <- ok
		}()
	}
	for pcacheWaiters(c) < n {
		time.Sleep(time.Millisecond)
	}
	c.Put(Entry{PID: 4})
	wg.Wait()
	close(got)
	for ok := range got {
		if !ok {
			t.Error("a waiter was not woken by the Put")
		}
	}
}

// Concurrent feeding and lookups; run with -race.
func TestPcacheConcurrent(t *testing.T) {
	c := New(64, time.Minute)
	c.AddFeeder()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				c.Put(Entry{PID: uint32(w*1000 + i%100)})
			}
		}(w)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				c.Get(uint32(w*1000 + i))
				c.Wait(uint32(w*1000+i), time.Millisecond)
			}
		}(w)
	}
	wg.Wait()
	if n := c.Len(); n > 64 {
		t.Errorf("Len = %d, above the bound", n)
	}
}

func pcacheWaiters(c *Cache) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, ws := range c.waiters {
		n += len(ws)
	}
	return n
}
