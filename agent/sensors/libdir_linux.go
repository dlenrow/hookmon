//go:build linux

package sensors

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/pkg/event"
)

// rootFS is a process's view of the filesystem: paths resolve under its
// root directory (/proc/<pid>/root), with absolute symlinks and ".." kept
// inside it, as the process itself resolves them. A container's library
// directories are judged in the container, not at the same path on the host.
type rootFS struct{ fd int }

// openRootFS opens root, a /proc/<pid>/root directory, for lookups. The
// caller closes it.
func openRootFS(root string) (rootFS, error) {
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return rootFS{fd: -1}, err
	}
	return rootFS{fd: fd}, nil
}

func (r rootFS) close() {
	if r.fd >= 0 {
		unix.Close(r.fd)
	}
}

// inRoot opens path O_PATH under the root. /proc magic links, which would
// name the bus's own files, are refused.
func (r rootFS) inRoot(path string, flags uint64) (int, error) {
	return unix.Openat2(r.fd, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC | flags,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
}

func (r rootFS) stat(path string) (uid, gid uint32, mode os.FileMode, ok bool) {
	fd, err := r.inRoot(path, 0)
	if err != nil {
		return 0, 0, 0, false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, 0, 0, false
	}
	return st.Uid, st.Gid, unixFileMode(st.Mode), true
}

// rootFSMaxLinks is the most symlinks realPath follows, as the kernel's
// MAXSYMLINKS.
const rootFSMaxLinks = 40

// realPath resolves every symlink in path, one component at a time, each
// read inside the root.
func (r rootFS) realPath(path string) (string, error) {
	resolved := "/"
	rest := pathComponents(path)
	for links := 0; len(rest) > 0; {
		name := rest[0]
		rest = rest[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		dir, err := r.inRoot(resolved, unix.O_DIRECTORY)
		if err != nil {
			return "", err
		}
		target, err := readlinkat(dir, name)
		unix.Close(dir)
		switch {
		case errors.Is(err, unix.EINVAL): // not a symlink
			resolved = filepath.Join(resolved, name)
			continue
		case err != nil:
			return "", err
		}
		if links++; links > rootFSMaxLinks {
			return "", unix.ELOOP
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		rest = append(pathComponents(target), rest...)
	}
	return resolved, nil
}

func pathComponents(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}

func readlinkat(dirfd int, name string) (string, error) {
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// unixFileMode converts a stat mode to os.FileMode: permission bits, the
// directory type, and the sticky, setuid and setgid bits.
func unixFileMode(m uint32) os.FileMode {
	mode := os.FileMode(m & 0o777)
	if m&unix.S_IFMT == unix.S_IFDIR {
		mode |= os.ModeDir
	}
	if m&unix.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	if m&unix.S_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if m&unix.S_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	return mode
}

// libraryFileRisk ranks the library file at path (already resolved in fs)
// by who can change it: its directory as an RPATH entry naming it would be
// ranked, and the file itself, which a non-root owner or a writing group or
// world can rewrite in place even in a root-only directory.
func libraryFileRisk(fs libFS, path string) (event.RpathRisk, string) {
	if uid, _, mode, ok := fs.stat(path); ok {
		switch {
		case mode.Perm()&0o002 != 0:
			return event.RpathRiskHigh, path + " is world-writable"
		case uid != 0:
			return event.RpathRiskMedium, path + " is owned by a non-root user"
		case mode.Perm()&0o020 != 0:
			return event.RpathRiskMedium, path + " is writable by its group"
		}
	}
	e := classifyEntryIn(fs, filepath.Dir(path), "", false, false)
	return e.Risk, e.Reason
}

// searchPathRisk returns the highest risk among the entries of an
// LD_LIBRARY_PATH value, each ranked as an RPATH entry is, in fs. ld.so
// splits the value at colons and semicolons; an empty entry is the working
// directory, but an empty value sets no path at all. binaryDir is the
// directory of the binary exec'd, for $ORIGIN; when it is unknown an entry
// that uses a token is ranked MEDIUM, since where it points is unknown.
func searchPathRisk(fs libFS, value, binaryDir string) (event.RpathRisk, string) {
	if value == "" {
		return event.RpathRiskNone, "empty value"
	}
	worst, why := event.RpathRiskNone, "standard library directories only"
	for _, entry := range splitSearchPath(value) {
		var risk event.RpathRisk
		var reason string
		if binaryDir == "" && strings.Contains(entry, "$") {
			risk, reason = event.RpathRiskMedium, "uses a token, and the binary's directory is unknown"
		} else {
			e := classifyEntryIn(fs, entry, binaryDir, false, false)
			risk, reason = e.Risk, e.Reason
		}
		if riskLevel(risk) > riskLevel(worst) {
			worst, why = risk, entry+": "+reason
		}
	}
	return worst, why
}

// splitSearchPath splits an LD_LIBRARY_PATH value into its entries, keeping
// empty ones: "a::b" and "a:" each have an empty entry, which ld.so reads
// as the working directory.
func splitSearchPath(value string) []string {
	var out []string
	start := 0
	for i := 0; i < len(value); i++ {
		if value[i] == ':' || value[i] == ';' {
			out = append(out, value[start:i])
			start = i + 1
		}
	}
	return append(out, value[start:])
}
