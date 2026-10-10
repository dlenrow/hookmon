package sensors

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The fixtures were written by glibc 2.36's ldconfig (Ubuntu 22.10) in a
// scratch root holding /usr/lib/libhmfixture.so.1 and, via ld.so.conf,
// /opt/hm/libhmother.so.2:
//
//	ldconfig -r root                                  # ldcache_new.bin
//	ldconfig -r root -c compat -C /etc/ld.so.cache.compat  # ldcache_compat.bin
//	ldconfig -r root -c old -C /etc/ld.so.cache.old        # ldcache_old.bin
var fixtureEntries = []ldCacheEntry{
	{Flags: 0x0303, Key: "libhmother.so.2", Value: "/opt/hm/libhmother.so.2"},
	{Flags: 0x0303, Key: "libhmfixture.so.1", Value: "/usr/lib/libhmfixture.so.1"},
}

func TestParseLdCacheFixtures(t *testing.T) {
	for _, name := range []string{"ldcache_new.bin", "ldcache_compat.bin", "ldcache_old.bin"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseLdCache(data)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(got) != len(fixtureEntries) {
				t.Fatalf("got %d entries %+v, want %d", len(got), got, len(fixtureEntries))
			}
			for i, want := range fixtureEntries {
				if got[i] != want {
					t.Errorf("entry %d = %+v, want %+v", i, got[i], want)
				}
			}
			// Every truncation must fail cleanly or parse, never panic.
			for n := 0; n < len(data); n++ {
				parseLdCache(data[:n])
			}
		})
	}
}

func TestParseLdCacheRejectsGarbage(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		[]byte("not a cache"),
		[]byte(ldCacheMagicNew), // header cut short
		append([]byte(ldCacheMagicOld+"\x00"), 0xff, 0xff, 0xff, 0x7f), // entry count overruns
	} {
		if _, err := parseLdCache(data); err == nil {
			t.Errorf("parseLdCache(%q) accepted", data)
		}
	}

	// An entry whose string offset points outside the file.
	data, err := os.ReadFile(filepath.Join("testdata", "ldcache_new.bin"))
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(data[ldCacheNewHeaderLen+8:], 1<<20)
	if _, err := parseLdCache(data); err == nil {
		t.Error("out-of-range string offset accepted")
	}
}

// buildNewLdCache writes a new-format cache with the given byte order and
// endianness flag.
func buildNewLdCache(bo binary.ByteOrder, flag byte, entries []ldCacheEntry) []byte {
	strOff := ldCacheNewHeaderLen + len(entries)*ldCacheNewEntryLen
	var strs []byte
	buf := make([]byte, strOff)
	copy(buf, ldCacheMagicNew)
	bo.PutUint32(buf[20:24], uint32(len(entries)))
	buf[28] = flag
	for i, e := range entries {
		ent := buf[ldCacheNewHeaderLen+i*ldCacheNewEntryLen:]
		bo.PutUint32(ent[0:4], uint32(e.Flags))
		bo.PutUint32(ent[4:8], uint32(strOff+len(strs)))
		strs = append(append(strs, e.Key...), 0)
		bo.PutUint32(ent[8:12], uint32(strOff+len(strs)))
		strs = append(append(strs, e.Value...), 0)
		bo.PutUint64(ent[16:24], e.Hwcap)
	}
	bo.PutUint32(buf[24:28], uint32(len(strs)))
	return append(buf, strs...)
}

func TestParseLdCacheByteOrder(t *testing.T) {
	want := []ldCacheEntry{{Flags: 0x0303, Key: "libz.so.1", Value: "/lib/libz.so.1", Hwcap: 1 << 40}}
	for _, tc := range []struct {
		name string
		bo   binary.ByteOrder
		flag byte
	}{
		{"little", binary.LittleEndian, 2},
		{"big", binary.BigEndian, 3},
		{"unset", binary.NativeEndian, 0},
	} {
		got, err := parseLdCache(buildNewLdCache(tc.bo, tc.flag, want))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if len(got) != 1 || got[0] != want[0] {
			t.Errorf("%s: got %+v", tc.name, got)
		}
	}
	if _, err := parseLdCache(buildNewLdCache(binary.LittleEndian, 1, want)); err == nil {
		t.Error("invalid endianness flag accepted")
	}
}

// TestLdCacheIndex checks that a library is found under the path the cache
// lists, under its symlink-resolved directory, and as the file the soname
// link points to, and that a rewritten cache is re-read.
func TestLdCacheIndex(t *testing.T) {
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(tmp, "usr", "lib")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/lib", filepath.Join(tmp, "lib")); err != nil { // like /lib -> usr/lib
		t.Fatal(err)
	}
	for _, f := range []string{"libx.so.1.2.3", "liby.so.2", "other.so"} {
		if err := os.WriteFile(filepath.Join(real, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("libx.so.1.2.3", filepath.Join(real, "libx.so.1")); err != nil {
		t.Fatal(err)
	}

	cachePath := filepath.Join(tmp, "ld.so.cache")
	write := func(entries []ldCacheEntry) {
		t.Helper()
		if err := os.WriteFile(cachePath, buildNewLdCache(binary.LittleEndian, 2, entries), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write([]ldCacheEntry{{Key: "libx.so.1", Value: filepath.Join(tmp, "lib", "libx.so.1")}})

	idx := newLdCacheIndex(cachePath)
	for p, want := range map[string]bool{
		filepath.Join(tmp, "lib", "libx.so.1"): true,  // as listed
		filepath.Join(real, "libx.so.1"):       true,  // listed name, real directory
		filepath.Join(real, "libx.so.1.2.3"):   true,  // what the loader maps
		filepath.Join(real, "liby.so.2"):       false, // not in the cache
		filepath.Join(real, "other.so"):        false,
	} {
		if got := idx.contains(p); got != want {
			t.Errorf("contains(%s) = %v, want %v", p, got, want)
		}
	}

	write([]ldCacheEntry{
		{Key: "libx.so.1", Value: filepath.Join(tmp, "lib", "libx.so.1")},
		{Key: "liby.so.2", Value: filepath.Join(tmp, "lib", "liby.so.2")},
	})
	if !idx.contains(filepath.Join(real, "liby.so.2")) {
		t.Error("rewritten cache was not re-read")
	}

	os.Remove(cachePath)
	if idx.contains(filepath.Join(real, "libx.so.1")) {
		t.Error("contains true with no cache file")
	}
}

// TestParseSystemLdCache parses the host's cache when there is one.
func TestParseSystemLdCache(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("no ld.so.cache outside Linux")
	}
	data, err := os.ReadFile("/etc/ld.so.cache")
	if err != nil {
		t.Skipf("no system ld.so.cache: %v", err)
	}
	entries, err := parseLdCache(data)
	if err != nil {
		t.Fatalf("parse /etc/ld.so.cache: %v", err)
	}
	for _, e := range entries {
		if e.Key == "libc.so.6" {
			return
		}
	}
	t.Errorf("libc.so.6 not among %d entries of /etc/ld.so.cache", len(entries))
}
