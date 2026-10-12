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
	"runtime"
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

// Writable/attacker-controlled directories. Each one, and everything under
// it, is dangerous.
var dangerousDirs = []string{
	"/tmp",
	"/var/tmp",
	"/dev/shm",
	"/home",
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
	key     FileID
	result  RpathResult
	emitted bool // an event for this binary version has been sent
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
		e := el.Value.(*rpathCacheEntry)
		e.result = result
		e.emitted = false
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

// claimEmit marks the binary version key as reported and returns true if
// it had not been reported yet. A key not in the cache is always reported.
// An entry evicted from the cache is reported again on its next exec.
func (c *RpathCache) claimEmit(key FileID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return true
	}
	e := el.Value.(*rpathCacheEntry)
	if e.emitted {
		return false
	}
	e.emitted = true
	return true
}

// unclaimEmit undoes claimEmit for an event that could not be delivered,
// so the next exec of the binary reports it.
func (c *RpathCache) unclaimEmit(key FileID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		el.Value.(*rpathCacheEntry).emitted = false
	}
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
			if _, origin := expandDST(p, binaryDir); origin {
				detail.UsesOrigin = true
			}
		}
	}

	if hasRunpath {
		detail.RunpathRaw = runpath[0]
		for _, p := range strings.Split(runpath[0], ":") {
			entry := classifyEntry(p, binaryDir, false, isSetuid)
			detail.Entries = append(detail.Entries, entry)
			if _, origin := expandDST(p, binaryDir); origin {
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

// libFS is the filesystem a library directory is judged in. An RPATH entry
// is judged in the bus's own (hostFS). The directories a process loads
// libraries from are judged as that process sees them: a container's own
// files, not the host's files at the same path (rootFS, Linux).
type libFS interface {
	// stat returns the owner, group and mode (type, permission and sticky
	// bits) of path, following symlinks as ld.so does.
	stat(path string) (uid, gid uint32, mode os.FileMode, ok bool)
	// realPath returns path with every symlink resolved.
	realPath(path string) (string, error)
}

// hostFS is the bus's own view of the filesystem.
type hostFS struct{}

func (hostFS) stat(path string) (uint32, uint32, os.FileMode, bool) { return dirOwner(path) }
func (hostFS) realPath(path string) (string, error)                 { return filepath.EvalSymlinks(path) }

// fsDirExists reports whether path is an existing directory in fs.
func fsDirExists(fs libFS, path string) bool {
	_, _, mode, ok := fs.stat(path)
	return ok && mode.IsDir()
}

// fsWorldWritable reports whether path exists in fs with the other-write bit.
func fsWorldWritable(fs libFS, path string) bool {
	_, _, mode, ok := fs.stat(path)
	return ok && mode.Perm()&0o002 != 0
}

// classifyEntry evaluates a single RPATH/RUNPATH path entry and assigns a risk level.
// Dynamic string tokens ($ORIGIN, $LIB, $PLATFORM, also as ${NAME}) are
// expanded first, as ld.so expands them.
func classifyEntry(path, binaryDir string, isRpath, isSetuid bool) event.RpathEntry {
	return classifyEntryIn(hostFS{}, path, binaryDir, isRpath, isSetuid)
}

// classifyEntryIn is classifyEntry with the directories looked up in fs.
func classifyEntryIn(fs libFS, path, binaryDir string, isRpath, isSetuid bool) event.RpathEntry {
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

	expanded, usesOrigin := expandDST(path, binaryDir)

	// An $ORIGIN path is only as safe as the directory it resolves to, so
	// one that resolves into a writable location is flagged like that
	// absolute path would be.
	if usesOrigin {
		resolved := filepath.Clean(expanded)
		entry.Exists = fsDirExists(fs, resolved)
		prefix := dangerousPrefix(resolved)
		switch {
		case isSetuid:
			entry.Risk = event.RpathRiskCritical
			entry.Reason = "$ORIGIN in SUID/SGID binary allows privilege escalation"
		case prefix != "":
			entry.Risk = event.RpathRiskCritical
			entry.Reason = fmt.Sprintf("$ORIGIN resolves to %s, in writable/attacker-controlled directory %s", resolved, prefix)
		case entry.Exists && fsWorldWritable(fs, resolved):
			entry.Risk = event.RpathRiskHigh
			entry.Reason = fmt.Sprintf("$ORIGIN resolves to world-writable directory %s", resolved)
		case entry.Exists:
			risk, why := writableRiskIn(fs, resolved)
			entry.Risk = risk
			entry.Reason = fmt.Sprintf("$ORIGIN-relative path in non-SUID binary, resolves to %s: %s", resolved, why)
		default:
			entry.Risk = event.RpathRiskLow
			entry.Reason = "$ORIGIN-relative path in non-SUID binary"
		}
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Relative path (no leading /).
	if !filepath.IsAbs(expanded) {
		entry.Risk = event.RpathRiskCritical
		entry.Reason = "relative path allows attacker-controlled library loading"
		entry.Exists = fsDirExists(fs, expanded)
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Check dangerous prefixes.
	cleaned := filepath.Clean(expanded)
	if prefix := dangerousPrefix(cleaned); prefix != "" {
		entry.Risk = event.RpathRiskCritical
		entry.Reason = fmt.Sprintf("writable/attacker-controlled directory: %s", prefix)
		entry.Exists = fsDirExists(fs, cleaned)
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Check if this is a standard system library path first (before exists check).
	if standardLibDirs[cleaned] {
		entry.Exists = fsDirExists(fs, cleaned)
		entry.Risk = event.RpathRiskNone
		entry.Reason = "standard system library directory"
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Check if directory exists.
	entry.Exists = fsDirExists(fs, cleaned)

	if !entry.Exists {
		entry.Risk = event.RpathRiskHigh
		entry.Reason = "non-existent directory (attacker could create it)"
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Check for world-writable directory.
	if fsWorldWritable(fs, cleaned) {
		entry.Risk = event.RpathRiskHigh
		entry.Reason = "world-writable directory"
		entry = bumpIfDeprecated(entry)
		return entry
	}

	// Non-standard but existing: ranked by who can write to it.
	risk, why := writableRiskIn(fs, cleaned)
	entry.Risk = risk
	entry.Reason = "non-standard library directory: " + why
	entry = bumpIfDeprecated(entry)
	return entry
}

// writableRisk ranks an existing library directory by who can change what
// ld.so finds there. Only root: LOW, no event. A non-root owner or a writing
// group: MEDIUM. The directories above it count too, because whoever can
// write a parent can rename the library directory and put another in its
// place. A sticky parent (like /tmp) protects entries its writers do not
// own, so only its owner counts; the library directory itself gets no such
// pass, since adding a file is enough there.
func writableRisk(dir string) (event.RpathRisk, string) {
	return writableRiskIn(hostFS{}, dir)
}

// writableRiskIn is writableRisk with the directories looked up in fs.
func writableRiskIn(fs libFS, dir string) (event.RpathRisk, string) {
	real, err := fs.realPath(dir)
	if err != nil {
		return event.RpathRiskMedium, fmt.Sprintf("cannot resolve %s: %v", dir, err)
	}
	for d, leaf := real, true; ; d, leaf = filepath.Dir(d), false {
		uid, gid, mode, ok := fs.stat(d)
		protected := !leaf && mode&os.ModeSticky != 0
		switch {
		case !ok:
			return event.RpathRiskMedium, fmt.Sprintf("owner of %s unknown", d)
		case mode&0o002 != 0 && !protected:
			return event.RpathRiskHigh, fmt.Sprintf("%s is world-writable", d)
		case uid != 0:
			return event.RpathRiskMedium, fmt.Sprintf("%s owned by uid %d", d, uid)
		case mode&0o020 != 0 && !protected:
			return event.RpathRiskMedium, fmt.Sprintf("%s writable by gid %d", d, gid)
		}
		if d == "/" || d == "." {
			return event.RpathRiskLow, "writable only by root"
		}
	}
}

// expandDST expands the dynamic string tokens ld.so substitutes in an
// RPATH/RUNPATH entry: $ORIGIN (the binary's directory, binaryDir), $LIB
// and $PLATFORM, each also written ${NAME}. As in glibc, a bare name
// followed by an identifier character is not a token, and a "$" that does
// not start a token is kept as is. It reports whether $ORIGIN was used.
func expandDST(path, binaryDir string) (string, bool) {
	if !strings.Contains(path, "$") {
		return path, false
	}
	var b strings.Builder
	usesOrigin := false
	for i := 0; i < len(path); {
		if path[i] != '$' {
			b.WriteByte(path[i])
			i++
			continue
		}
		name, n := dstAt(path[i+1:])
		switch name {
		case "ORIGIN":
			b.WriteString(binaryDir)
			usesOrigin = true
		case "LIB":
			b.WriteString(hostDST().lib)
		case "PLATFORM":
			b.WriteString(hostDST().platform)
		default:
			b.WriteByte('$')
			i++
			continue
		}
		i += 1 + n
	}
	return b.String(), usesOrigin
}

// dstAt returns the token name at the start of s, which follows a "$", and
// the length it takes up in s, or "" if there is none.
func dstAt(s string) (string, int) {
	for _, name := range []string{"ORIGIN", "LIB", "PLATFORM"} {
		if strings.HasPrefix(s, "{"+name+"}") {
			return name, len(name) + 2
		}
		if strings.HasPrefix(s, name) && (len(s) == len(name) || !isIdentByte(s[len(name)])) {
			return name, len(name)
		}
	}
	return "", 0
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// dstValues are this host's expansions of $LIB and $PLATFORM.
type dstValues struct {
	lib      string
	platform string
}

// hostDST works out $LIB and $PLATFORM for native binaries on this host.
// $LIB is compiled into ld.so: "lib/<multiarch>" on Debian and Ubuntu,
// "lib64" on Fedora, RHEL and SUSE, "lib" on Arch. $PLATFORM is the
// kernel's AT_PLATFORM, the machine name for native binaries.
var hostDST = sync.OnceValue(func() dstValues {
	machine, multiarch := runtime.GOARCH, ""
	switch runtime.GOARCH {
	case "amd64":
		machine, multiarch = "x86_64", "x86_64-linux-gnu"
	case "arm64":
		machine, multiarch = "aarch64", "aarch64-linux-gnu"
	case "386":
		machine, multiarch = "i686", "i386-linux-gnu"
	case "arm":
		machine, multiarch = "v7l", "arm-linux-gnueabihf"
	case "ppc64le":
		multiarch = "powerpc64le-linux-gnu"
	case "s390x":
		multiarch = "s390x-linux-gnu"
	case "riscv64":
		multiarch = "riscv64-linux-gnu"
	}
	v := dstValues{lib: "lib", platform: machine}
	if multiarch != "" && (dirExists("/usr/lib/"+multiarch) || dirExists("/lib/"+multiarch)) {
		v.lib = "lib/" + multiarch
	} else if fi, err := os.Lstat("/usr/lib64"); err == nil && fi.IsDir() {
		// A real directory, not Arch's lib64 -> lib symlink.
		v.lib = "lib64"
	}
	return v
})

// bumpIfDeprecated raises the risk one level if the entry uses DT_RPATH
// (deprecated). It never lifts LOW to MEDIUM: a directory only root can
// write stays below the event threshold whichever tag names it.
func bumpIfDeprecated(entry event.RpathEntry) event.RpathEntry {
	if !entry.IsRpath {
		return entry
	}
	switch entry.Risk {
	case event.RpathRiskNone:
		entry.Risk = event.RpathRiskLow
		entry.Reason += " [+deprecated DT_RPATH]"
	case event.RpathRiskLow:
		entry.Reason += " [deprecated DT_RPATH]"
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

// dangerousPrefix returns the entry of dangerousDirs that path, once
// cleaned, is or is under, or "". The match is by whole path component:
// /tmp and /tmp/x match, /tmpfoo does not.
func dangerousPrefix(path string) string {
	cleaned := filepath.Clean(path)
	for _, dir := range dangerousDirs {
		if cleaned == dir || strings.HasPrefix(cleaned, dir+"/") {
			return dir
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
