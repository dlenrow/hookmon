package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Parser for glibc's /etc/ld.so.cache, after elf/dl-cache.h. Three layouts
// exist:
//
//   - old ("ld.so-1.7.0"): 16-byte header, 12-byte entries, then the string
//     table; string offsets are relative to the end of the entries.
//   - new ("glibc-ld.so.cache1.1"): 48-byte header, 24-byte entries, string
//     offsets relative to the start of the new header. glibc 2.32 and later
//     write only this format by default.
//   - compat: an old table followed, at the next 8-byte boundary, by a new
//     one. The new table is the one parsed.
const (
	ldCacheMagicOld     = "ld.so-1.7.0"
	ldCacheMagicNew     = "glibc-ld.so.cache1.1"
	ldCacheOldHeaderLen = 16
	ldCacheOldEntryLen  = 12
	ldCacheNewHeaderLen = 48
	ldCacheNewEntryLen  = 24
)

// ldCacheEntry is one library listed in ld.so.cache.
type ldCacheEntry struct {
	Flags int32
	Key   string // soname, e.g. libc.so.6
	Value string // path the loader opens, e.g. /lib/x86_64-linux-gnu/libc.so.6
	Hwcap uint64 // new format only
}

func parseLdCache(data []byte) ([]ldCacheEntry, error) {
	if bytes.HasPrefix(data, []byte(ldCacheMagicNew)) {
		return parseLdCacheNew(data, 0)
	}
	if !bytes.HasPrefix(data, []byte(ldCacheMagicOld)) {
		return nil, errors.New("ld.so.cache: unknown magic")
	}
	if len(data) < ldCacheOldHeaderLen {
		return nil, errors.New("ld.so.cache: short old-format header")
	}
	// The old format has no endianness flag; it is written in host order.
	bo := binary.NativeEndian
	nlibs := bo.Uint32(data[12:16])
	if uint64(nlibs) > uint64(len(data)-ldCacheOldHeaderLen)/ldCacheOldEntryLen {
		return nil, fmt.Errorf("ld.so.cache: %d old-format entries overrun the file", nlibs)
	}
	end := ldCacheOldHeaderLen + int(nlibs)*ldCacheOldEntryLen
	if newOff := (end + 7) &^ 7; newOff < len(data) && bytes.HasPrefix(data[newOff:], []byte(ldCacheMagicNew)) {
		return parseLdCacheNew(data, newOff)
	}
	strtab := data[end:]
	entries := make([]ldCacheEntry, 0, nlibs)
	for i := 0; i < int(nlibs); i++ {
		e := data[ldCacheOldHeaderLen+i*ldCacheOldEntryLen:]
		key, err := cString(strtab, bo.Uint32(e[4:8]))
		if err != nil {
			return nil, err
		}
		val, err := cString(strtab, bo.Uint32(e[8:12]))
		if err != nil {
			return nil, err
		}
		entries = append(entries, ldCacheEntry{Flags: int32(bo.Uint32(e[0:4])), Key: key, Value: val})
	}
	return entries, nil
}

// parseLdCacheNew parses a new-format table starting at data[base:].
func parseLdCacheNew(data []byte, base int) ([]ldCacheEntry, error) {
	d := data[base:]
	if len(d) < ldCacheNewHeaderLen {
		return nil, errors.New("ld.so.cache: short new-format header")
	}
	var bo binary.ByteOrder
	switch d[28] & 3 { // cache_file_new_flags_endian_mask
	case 0: // unset: written by a glibc older than 2.33, in host order
		bo = binary.NativeEndian
	case 2:
		bo = binary.LittleEndian
	case 3:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("ld.so.cache: invalid endianness flag %#x", d[28])
	}
	nlibs := bo.Uint32(d[20:24])
	if uint64(nlibs) > uint64(len(d)-ldCacheNewHeaderLen)/ldCacheNewEntryLen {
		return nil, fmt.Errorf("ld.so.cache: %d entries overrun the file", nlibs)
	}
	entries := make([]ldCacheEntry, 0, nlibs)
	for i := 0; i < int(nlibs); i++ {
		e := d[ldCacheNewHeaderLen+i*ldCacheNewEntryLen:]
		key, err := cString(d, bo.Uint32(e[4:8]))
		if err != nil {
			return nil, err
		}
		val, err := cString(d, bo.Uint32(e[8:12]))
		if err != nil {
			return nil, err
		}
		entries = append(entries, ldCacheEntry{
			Flags: int32(bo.Uint32(e[0:4])),
			Key:   key,
			Value: val,
			Hwcap: bo.Uint64(e[16:24]),
		})
	}
	return entries, nil
}

func cString(tab []byte, off uint32) (string, error) {
	if uint64(off) >= uint64(len(tab)) {
		return "", fmt.Errorf("ld.so.cache: string offset %d outside table of %d bytes", off, len(tab))
	}
	s := tab[off:]
	i := bytes.IndexByte(s, 0)
	if i < 0 {
		return "", fmt.Errorf("ld.so.cache: unterminated string at offset %d", off)
	}
	return string(s[:i]), nil
}

// ldCachePaths returns every path under which a cached library can be found:
// the path as listed, the same name in the symlink-resolved directory (the
// cache lists /lib/x86_64-linux-gnu/... where /lib links to /usr/lib), and
// the file the listed path finally resolves to (libfoo.so.1 is usually a link
// to libfoo.so.1.2.3, which is what the loader maps).
func ldCachePaths(entries []ldCacheEntry) map[string]bool {
	set := make(map[string]bool, 3*len(entries))
	realDirs := make(map[string]string)
	for _, e := range entries {
		if e.Value == "" {
			continue
		}
		v := filepath.Clean(e.Value)
		set[v] = true
		dir := filepath.Dir(v)
		real, ok := realDirs[dir]
		if !ok {
			var err error
			if real, err = filepath.EvalSymlinks(dir); err != nil {
				real = dir
			}
			realDirs[dir] = real
		}
		set[filepath.Join(real, filepath.Base(v))] = true
		if target, err := filepath.EvalSymlinks(v); err == nil {
			set[target] = true
		}
	}
	return set
}

// ldCacheIndex answers whether a library path is in ld.so.cache. It re-reads
// the cache whenever the file is replaced or changes size or mtime, which
// ldconfig always does when it rewrites it.
type ldCacheIndex struct {
	path string

	mu    sync.Mutex
	stamp os.FileInfo
	paths map[string]bool
}

func newLdCacheIndex(path string) *ldCacheIndex {
	return &ldCacheIndex{path: path}
}

func (c *ldCacheIndex) contains(p string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refresh()
	return c.paths[filepath.Clean(p)]
}

func (c *ldCacheIndex) refresh() {
	fi, err := os.Stat(c.path)
	if err != nil {
		c.stamp, c.paths = nil, nil
		return
	}
	if c.stamp != nil && os.SameFile(c.stamp, fi) && c.stamp.Size() == fi.Size() && c.stamp.ModTime().Equal(fi.ModTime()) {
		return
	}
	c.stamp, c.paths = fi, nil
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	entries, err := parseLdCache(data)
	if err != nil {
		return
	}
	c.paths = ldCachePaths(entries)
}
