// Package sensors — elf_rpath implements ELF RPATH/RUNPATH analysis.
// This is a pure-Go userspace analyzer (no eBPF, no build tags) that uses
// debug/elf to inspect DT_RPATH and DT_RUNPATH entries in ELF binaries.
// It runs as a post-enrichment audit on execve events, not as a standalone sensor.
package sensors

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Standard system library directories considered safe.
var standardLibDirs = map[string]bool{
	"/usr/lib":       true,
	"/usr/lib64":     true,
	"/usr/lib32":     true,
	"/lib":           true,
	"/lib64":         true,
	"/lib32":         true,
	"/usr/local/lib": true,
	"/usr/local/lib64": true,
}

// Writable/attacker-controlled directories.
var dangerousPrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
	"/home/",
}

// rpathCacheKey identifies a cached analysis by path, inode, and mtime.
type rpathCacheKey struct {
	path  string
	inode uint64
	mtime int64
}

// RpathCache is a thread-safe LRU-ish cache for RPATH analysis results.
type RpathCache struct {
	mu      sync.Mutex
	entries map[rpathCacheKey]*event.ElfRpathDetail
	maxSize int
}

// NewRpathCache creates a cache with the given maximum number of entries.
func NewRpathCache(maxSize int) *RpathCache {
	return &RpathCache{
		entries: make(map[rpathCacheKey]*event.ElfRpathDetail, maxSize),
		maxSize: maxSize,
	}
}

// Get returns a cached result if found, or nil.
func (c *RpathCache) Get(path string, inode uint64, mtime int64) *event.ElfRpathDetail {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries[rpathCacheKey{path, inode, mtime}]
}

// Put stores a result. If the cache is full, it evicts an arbitrary entry.
func (c *RpathCache) Put(path string, inode uint64, mtime int64, detail *event.ElfRpathDetail) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		// Evict one arbitrary entry.
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[rpathCacheKey{path, inode, mtime}] = detail
}

// Len returns the number of cached entries.
func (c *RpathCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// AnalyzeElfRpath opens an ELF binary and analyzes its DT_RPATH and DT_RUNPATH entries.
// Returns nil detail (no error) if the file is not ELF or has no RPATH/RUNPATH.
func AnalyzeElfRpath(exePath string) (*event.ElfRpathDetail, error) {
	f, err := elf.Open(exePath)
	if err != nil {
		// Not an ELF binary or unreadable — not an error for our purposes.
		return nil, nil
	}
	defer f.Close()

	rpath, rpathErr := f.DynString(elf.DT_RPATH)
	runpath, runpathErr := f.DynString(elf.DT_RUNPATH)

	// If neither is present, nothing to report.
	hasRpath := rpathErr == nil && len(rpath) > 0 && rpath[0] != ""
	hasRunpath := runpathErr == nil && len(runpath) > 0 && runpath[0] != ""
	if !hasRpath && !hasRunpath {
		return nil, nil
	}

	binaryDir := filepath.Dir(exePath)
	isSetuid := checkSetuid(exePath)

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

	return detail, nil
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

	// Check if $ORIGIN is used.
	if strings.Contains(path, "$ORIGIN") {
		if isSetuid {
			entry.Risk = event.RpathRiskCritical
			entry.Reason = "$ORIGIN in SUID/SGID binary allows privilege escalation"
		} else {
			entry.Risk = event.RpathRiskLow
			entry.Reason = "$ORIGIN-relative path in non-SUID binary"
		}
		// Resolve $ORIGIN for exists check.
		resolved := strings.ReplaceAll(path, "$ORIGIN", binaryDir)
		entry.Exists = dirExists(resolved)
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
	for _, prefix := range dangerousPrefixes {
		if strings.HasPrefix(path, prefix) {
			entry.Risk = event.RpathRiskCritical
			entry.Reason = fmt.Sprintf("writable/attacker-controlled directory: %s", prefix)
			entry.Exists = dirExists(path)
			entry = bumpIfDeprecated(entry)
			return entry
		}
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

// checkSetuid checks if a file has SUID or SGID bits set.
func checkSetuid(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	mode := info.Mode()
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
	Path   string               `json:"path"`
	Detail *event.ElfRpathDetail `json:"detail,omitempty"`
	Error  string               `json:"error,omitempty"`
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

// FileInodeAndMtime returns the inode and mtime for a path, for cache keying.
func FileInodeAndMtime(path string) (inode uint64, mtime time.Time, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, time.Time{}, err
	}
	mtime = info.ModTime()
	// Try to get inode from platform-specific Sys()
	inode = fileInode(info)
	return inode, mtime, nil
}
