package allowlist

import (
	"fmt"
	"strings"

	"github.com/dlenrow/hookmon/pkg/event"
)

// File hashes (exe, library, and the linker_config and lib_integrity
// content hashes) are "sha256:<64 lowercase hex digits>" everywhere since
// step 4. A BPF program's ProgHash is the kernel program tag: 16 hex
// digits, as bpftool prints it.

const (
	sha256Prefix = "sha256:"
	sha256HexLen = 64
	progTagLen   = 16
)

// canonFileHash returns h in the bus's format when it is a SHA-256 in any
// accepted spelling (prefix in any case, or bare hex), and h lower-cased
// otherwise.
func canonFileHash(h string) string {
	if n, err := NormalizeFileHash(h); err == nil {
		return n
	}
	return lower(h)
}

// SameFileHash reports whether two file hashes name the same content. The
// "sha256:" prefix and letter case do not matter, so an entry written as
// bare hex matches the bus's "sha256:<hex>".
func SameFileHash(a, b string) bool {
	if a == b {
		return true
	}
	return canonFileHash(a) == canonFileHash(b)
}

// SameProgTag reports whether two BPF program tags are equal, ignoring
// letter case.
func SameProgTag(a, b string) bool {
	return a == b || strings.EqualFold(a, b)
}

// NormalizeFileHash returns h as "sha256:<64 lowercase hex digits>". It
// accepts that form with the prefix in any case, or the 64 hex digits
// alone. Anything else is an error: it could never match a hash the bus
// reports.
func NormalizeFileHash(h string) (string, error) {
	hexPart := h
	if len(h) >= len(sha256Prefix) && strings.EqualFold(h[:len(sha256Prefix)], sha256Prefix) {
		hexPart = h[len(sha256Prefix):]
	}
	if len(hexPart) != sha256HexLen || !isHex(hexPart) {
		return "", fmt.Errorf("%q is not a file hash: want sha256:<64 hex digits>", h)
	}
	return sha256Prefix + lower(hexPart), nil
}

// NormalizeProgTag returns a BPF program tag as 16 lowercase hex digits.
// Anything else is an error. In particular, a "sha256:" value written
// before step 4 is rejected: ProgHash is the kernel's tag now.
func NormalizeProgTag(t string) (string, error) {
	if len(t) != progTagLen || !isHex(t) {
		return "", fmt.Errorf("%q is not a BPF program tag: want 16 hex digits, as bpftool prog show prints it", t)
	}
	return lower(t), nil
}

// Normalize checks the hash criteria of an entry written by an operator
// and rewrites them in the formats the bus reports.
func Normalize(e *event.AllowlistEntry) error {
	if e.ExeHash != "" {
		h, err := NormalizeFileHash(e.ExeHash)
		if err != nil {
			return fmt.Errorf("exe_hash: %w", err)
		}
		e.ExeHash = h
	}
	if e.LibraryHash != "" {
		h, err := NormalizeFileHash(e.LibraryHash)
		if err != nil {
			return fmt.Errorf("library_hash: %w", err)
		}
		e.LibraryHash = h
	}
	if e.ProgHash != "" {
		t, err := NormalizeProgTag(e.ProgHash)
		if err != nil {
			return fmt.Errorf("prog_hash: %w", err)
		}
		e.ProgHash = t
	}
	return nil
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
