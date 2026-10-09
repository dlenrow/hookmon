// Package sensors — elf_rpath implements ELF RPATH/RUNPATH analysis.
// This file is the pure-Go analyzer (no eBPF, no build tags) that uses
// debug/elf to inspect DT_RPATH and DT_RUNPATH entries in ELF binaries, plus
// its cache. The elf_rpath sensor (elf_rpath_sensor.go) runs it on every exec
// its sched_process_exec program reports.
package sensors

import (
	"container/list"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Standard system library directories considered safe.
var standardLibDirs = map[string]bool{
	"/usr/lib":         true,
	"/usr/lib64":       true,
	"/usr/lib32":       true,
	"/lib":             true,
	"/lib64":           true,
	"/lib32":           true,
	"/usr/local/lib":   true,
	"/usr/local/lib64": true,
}

// Writable/attacker-controlled directories.
var dangerousPrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
	"/home/",
}

// rpathCacheCap bounds the sensor's analysis cache, one entry per binary
// version.
const rpathCacheCap = 10000

// FileID identifies one version of a file: its device, inode, mtime and
// mode. Rewriting the file in place changes the mtime; replacing it changes
// the inode. The mode is in the key because chmod u+s changes the
// classification ($ORIGIN in a setuid binary) without changing the mtime.
type FileID struct {
	Dev     uint64
	Ino     uint64
	MtimeNs int64
	Mode    uint32
}

// RpathResult is one cached analysis. Detail is nil when the binary has no
// RPATH/RUNPATH or is not ELF. Path is where the binary was analyzed; $ORIGIN
// was resolved against its directory.
type RpathResult struct {
	Detail *event.ElfRpathDetail
	Path   string
}

type rpathCacheEntry struct {
	key    FileID
	result RpathResult
}

// RpathCache is a thread-safe LRU cache of RPATH analysis results. It also
// holds negative results (no RPATH/RUNPATH, not ELF), the common case, so
// each version of a binary is analyzed once, not once per exec.
type RpathCache struct {
	mu      sync.Mutex
	maxSize int
	order   *list.List // front is most recently used; values are *rpathCacheEntry
	entries map[FileID]*list.Element
}

// NewRpathCache creates a cache with the given maximum number of entries.
func NewRpathCache(maxSize int) *RpathCache {
	if maxSize < 1 {
		maxSize = 1
	}
	return &RpathCache{
		maxSize: maxSize,
		order:   list.New(),
		entries: make(map[FileID]*list.Element, maxSize),
	}
}

// Get returns the cached result for key and whether there was one. A hit
// with a nil Detail is a cached negative result. A hit makes the entry the
// most recently used.
func (c *RpathCache) Get(key FileID) (RpathResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return RpathResult{}, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*rpathCacheEntry).result, true
}

// Put stores a result. If the cache is full, it evicts the least recently
// used entry.
func (c *RpathCache) Put(key FileID, result RpathResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		el.Value.(*rpathCacheEntry).result = result
		c.order.MoveToFront(el)
		return
	}
	if c.order.Len() >= c.maxSize {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*rpathCacheEntry).key)
	}
	c.entries[key] = c.order.PushFront(&rpathCacheEntry{key: key, result: result})
}

// Len returns the number of cached entries.
func (c *RpathCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// RpathSeverity maps the highest RPATH risk to an event severity, following
// the CLAUDE.md severity table: CRITICAL→CRITICAL, HIGH→ALERT, MEDIUM→WARN.
// Lower risks map to INFO; the sensor emits no event for them.
func RpathSeverity(risk event.RpathRisk) event.Severity {
	switch risk {
	case event.RpathRiskCritical:
		return event.SeverityCritical
	case event.RpathRiskHigh:
		return event.SeverityAlert
	case event.RpathRiskMedium:
		return event.SeverityWarn
	default:
		return event.SeverityInfo
	}
}

// AnalyzeElfRpath opens an ELF binary and analyzes its DT_RPATH and DT_RUNPATH entries.
// Returns nil detail (no error) if the file is not ELF or has no RPATH/RUNPATH.
func AnalyzeElfRpath(exePath string) (*event.ElfRpathDetail, error) {
	f, err := os.Open(exePath)
	if err != nil {
		// Unreadable — not an error for our purposes.
		return nil, nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil
	}
	return analyzeElfRpath(f, exePath, isSetuidMode(info.Mode())), nil
}

// analyzeElfRpath analyzes the ELF image in r. exePath is the binary's path,
// used to resolve $ORIGIN, and isSetuid says whether it has the SUID or SGID
// bit. Returns nil if r is not ELF or has no RPATH/RUNPATH.
func analyzeElfRpath(r io.ReaderAt, exePath string, isSetuid bool) *event.ElfRpathDetail {
	f, err := elf.NewFile(r)
	if err != nil {
		// Not an ELF binary — not an error for our purposes.
		return nil
	}
	defer f.Close()

	rpath, rpathErr := f.DynString(elf.DT_RPATH)
	runpath, runpathErr := f.DynString(elf.DT_RUNPATH)

	// If neither is present, nothing to report.
	hasRpath := rpathErr == nil && len(rpath) > 0 && rpath[0] != ""
	hasRunpath := runpathErr == nil && len(runpath) > 0 && runpath[0] != ""
	if !hasRpath && !hasRunpath {
		return nil
	}

	binaryDir := filepath.Dir(exePath)

	detail := &event.ElfRpathDetail{
		HasRpath:       hasRpath,
		HasRunpath:     hasRunpath,
		UsesDeprecated: hasRpath,
		IsSetuid:       isSetuid,
		HighestRisk:    event.RpathRiskNone,
	}

	if hasRpath {
		detail.RpathRaw = rpath[0]
		for _, p := range strings.Split(rpath[0], ":") {
			entry := classifyEntry(p, binaryDir, true, isSetuid)
			detail.Entries = append(detail.Entries, entry)
			if strings.Contains(p, "$ORIGIN") {
				detail.UsesOrigin = true
			}
		}
	}

	if hasRunpath {
		detail.RunpathRaw = runpath[0]
		for _, p := range strings.Split(runpath[0], ":") {
			entry := classifyEntry(p, binaryDir, false, isSetuid)
			detail.Entries = append(detail.Entries, entry)
			if strings.Contains(p, "$ORIGIN") {
				detail.UsesOrigin = true
			}
		}
	}

	// Compute highest risk across all entries.
	for _, e := range detail.Entries {
		if riskLevel(e.Risk) > riskLevel(detail.HighestRisk) {
			detail.HighestRisk = e.Risk
		}
	}

	return detail
}

// classifyEntry evaluates a single RPATH/RUNPATH path entry and assigns a risk level.
func classifyEntry(path, binaryDir string, isRpath, isSetuid bool) event.RpathEntry {
	entry := event.RpathEntry{
		Path:    path,
		IsRpath: isRpath,
	}

	// Empty entry (from double :: separator).
	if path == "" {
		entry.Risk = event.RpathRiskHigh
		entry.Reason = "empty path entry (equivalent to current directory)"
		return entry
	}

	// Check if $ORIGIN is used. An $ORIGIN path is only as safe as the
	// directory it resolves to, so one that resolves into a writable
	// location is flagged like that absolute path would be.
	if strings.Contains(path, "$ORIGIN") {
		resolved := filepath.Clean(strings.ReplaceAll(path, "$ORIGIN", binaryDir))
		entry.Exists = dirExists(resolved)
		prefix := dangerousPrefix(resolved + "/")
		switch {
		case isSetuid:
			entry.Risk = event.RpathRiskCritical
			entry.Reason = "$ORIGIN in SUID/SGID binary allows privilege escalation"
		case prefix != "":
			entry.Risk = event.RpathRiskCritical
			entry.Reason = fmt.Sprintf("$ORIGIN resolves to %s, in writable/attacker-controlled directory %s", resolved, prefix)
		case entry.Exists && isWorldWritable(resolved):
			entry.Risk = event.RpathRiskHigh
			entry.Reason = fmt.Sprintf("$ORIGIN resolves to world-writable directory %s", resolved)
		default:
			entry.Risk = event.RpathRiskLow
			entry.Reason = "$ORIGIN-relative path in non-SUID binary"
		}
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Relative path (no leading /).
	if !filepath.IsAbs(path) {
		entry.Risk = event.RpathRiskCritical
		entry.Reason = "relative path allows attacker-controlled library loading"
		entry.Exists = dirExists(path)
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Check dangerous prefixes.
	if prefix := dangerousPrefix(path); prefix != "" {
		entry.Risk = event.RpathRiskCritical
		entry.Reason = fmt.Sprintf("writable/attacker-controlled directory: %s", prefix)
		entry.Exists = dirExists(path)
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Check if this is a standard system library path first (before exists check).
	cleaned := filepath.Clean(path)
	if standardLibDirs[cleaned] {
		entry.Exists = dirExists(path)
		entry.Risk = event.RpathRiskNone
		entry.Reason = "standard system library directory"
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Check if directory exists.
	entry.Exists = dirExists(path)

	if !entry.Exists {
		entry.Risk = event.RpathRiskHigh
		entry.Reason = "non-existent directory (attacker could create it)"
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Check for world-writable directory.
	if isWorldWritable(path) {
		entry.Risk = event.RpathRiskHigh
		entry.Reason = "world-writable directory"
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Non-standard but exists and not obviously dangerous.
	entry.Risk = event.RpathRiskMedium
	entry.Reason = "non-standard library directory"
	entry = bumpIfDeprecated(entry)
	return entry
}

// bumpIfDeprecated raises the risk one level if the entry uses DT_RPATH (deprecated).
func bumpIfDeprecated(entry event.RpathEntry) event.RpathEntry {
	if !entry.IsRpath {
		return entry
	}
	switch entry.Risk {
	case event.RpathRiskNone:
		entry.Risk = event.RpathRiskLow
		entry.Reason += " [+deprecated DT_RPATH]"
	case event.RpathRiskLow:
		entry.Risk = event.RpathRiskMedium
		entry.Reason += " [+deprecated DT_RPATH]"
	case event.RpathRiskMedium:
		entry.Risk = event.RpathRiskHigh
		entry.Reason += " [+deprecated DT_RPATH]"
	case event.RpathRiskHigh:
		entry.Risk = event.RpathRiskCritical
		entry.Reason += " [+deprecated DT_RPATH]"
		// CRITICAL stays CRITICAL
	}
	return entry
}

// dangerousPrefix returns the entry of dangerousPrefixes that path starts
// with, or "".
func dangerousPrefix(path string) string {
	for _, prefix := range dangerousPrefixes {
		if strings.HasPrefix(path, prefix) {
			return prefix
		}
	}
	return ""
}

// isSetuidMode reports whether a file mode has the SUID or SGID bit set.
func isSetuidMode(mode os.FileMode) bool {
	return mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0
}

// dirExists checks if a path is an existing directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// isWorldWritable checks if a directory is world-writable (other-write bit set).
func isWorldWritable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0002 != 0
}

// riskLevel returns a numeric level for comparison.
func riskLevel(r event.RpathRisk) int {
	switch r {
	case event.RpathRiskNone:
		return 0
	case event.RpathRiskLow:
		return 1
	case event.RpathRiskMedium:
		return 2
	case event.RpathRiskHigh:
		return 3
	case event.RpathRiskCritical:
		return 4
	default:
		return 0
	}
}

// RiskBelow returns true if risk a is strictly below risk b.
func RiskBelow(a, b event.RpathRisk) bool {
	return riskLevel(a) < riskLevel(b)
}

// ScanResult is the output of scanning a single binary for RPATH issues.
type ScanResult struct {
	Path   string                `json:"path"`
	Detail *event.ElfRpathDetail `json:"detail,omitempty"`
	Error  string                `json:"error,omitempty"`
}

// ScanDirectory walks a directory tree and analyzes every ELF binary for RPATH issues.
// Only files with RPATH/RUNPATH entries (or errors) are included in the output.
func ScanDirectory(root string) []ScanResult {
	var results []ScanResult

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// Skip non-regular files.
		if !info.Mode().IsRegular() {
			return nil
		}
		// Skip very small files (unlikely to be ELF).
		if info.Size() < 64 {
			return nil
		}

		detail, analyzeErr := AnalyzeElfRpath(path)
		if analyzeErr != nil {
			results = append(results, ScanResult{Path: path, Error: analyzeErr.Error()})
			return nil
		}
		if detail != nil {
			results = append(results, ScanResult{Path: path, Detail: detail})
		}
		return nil
	})

	return results
}

// ScanDirectoryJSON runs ScanDirectory and returns JSON-encoded results.
func ScanDirectoryJSON(root string) ([]byte, error) {
	results := ScanDirectory(root)
	return json.MarshalIndent(results, "", "  ")
}
