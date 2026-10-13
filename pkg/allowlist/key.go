package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Subject kinds of a LearnedKey. Each kind names the mechanism and what
// the Subject field holds.
const (
	SubjectBPFTag        = "bpf_tag"
	SubjectBPFName       = "bpf_name"
	SubjectLDPreload     = "ld_preload"
	SubjectLDAudit       = "ld_audit"
	SubjectLDLibraryPath = "ld_library_path"
	SubjectLDDebug       = "ld_debug"
	SubjectScanTruncated = "scan_truncated"
	SubjectDlopen        = "dlopen"
	SubjectLibReplace    = "lib_replace"
	SubjectLinkerConfig  = "linker_config"
	SubjectSHMPattern    = "shm_pattern"
	SubjectSHMName       = "shm_name"
	SubjectRpath         = "rpath"
	SubjectPtrace        = "ptrace"
)

// KeyOf returns the learning-mode key of an event: what was loaded or
// changed. The acting binary, host, user and container are context on
// the event, not part of the key. BPF load, attach and inventory events
// share one key when they name the same program.
//
// The subject is, by mechanism:
//   - BPF (load, attach, inventory): the program tag + program type.
//     When the kernel gave no tag, the program name stands in.
//   - LD_PRELOAD, LD_AUDIT: the library's hash (or path when unhashed).
//   - LD_LIBRARY_PATH: the directory list value.
//   - LD_DEBUG: nothing (the variable name itself is the key).
//   - dlopen: the library's hash (or path when unhashed).
//   - Library replacement: the library path + new content hash.
//   - Linker config: the file path + new content hash.
//   - SHM: the bus's pattern for the segment name.
//   - RPATH: the binary's exe hash (the binary carries the RPATH).
//   - ptrace: the tracer's exe hash.
func KeyOf(evt *event.HookEvent) event.LearnedKey {
	var k event.LearnedKey
	switch evt.EventType {
	case event.EventBPFLoad, event.EventBPFAttach, event.EventBPFInventory:
		if d := evt.BPFDetail; d != nil {
			k.ProgType = d.ProgType
			if d.ProgHash != "" {
				k.SubjectKind, k.Subject = SubjectBPFTag, lower(d.ProgHash)
			} else {
				k.SubjectKind, k.Subject = SubjectBPFName, d.ProgName
			}
		}
	case event.EventExecInjection:
		if d := evt.ExecInjectionDetail; d != nil {
			if d.ScanTruncated {
				k.SubjectKind = SubjectScanTruncated
			} else {
				switch d.EnvVar {
				case "LD_AUDIT":
					k.SubjectKind = SubjectLDAudit
					k.Subject = libraryValue(d.LibraryHash, d.LibraryPath)
				case "LD_LIBRARY_PATH":
					k.SubjectKind = SubjectLDLibraryPath
					k.Subject = d.LibraryPath
				case "LD_DEBUG":
					k.SubjectKind = SubjectLDDebug
				default:
					k.SubjectKind = SubjectLDPreload
					k.Subject = libraryValue(d.LibraryHash, d.LibraryPath)
				}
			}
		}
	case event.EventDlopen:
		if d := evt.DlopenDetail; d != nil {
			k.SubjectKind = SubjectDlopen
			k.Subject = libraryValue(d.LibraryHash, d.LibraryPath)
		}
	case event.EventLibIntegrity:
		if d := evt.LibIntegrityDetail; d != nil {
			k.SubjectKind = SubjectLibReplace
			k.Subject = d.LibraryPath
			k.ContentHash = canonFileHash(d.NewHash)
		}
	case event.EventLinkerConfig:
		if d := evt.LinkerConfigDetail; d != nil {
			k.SubjectKind = SubjectLinkerConfig
			k.Subject = d.FilePath
			k.ContentHash = canonFileHash(d.NewHash)
		}
	case event.EventSHMCreate:
		if d := evt.SHMDetail; d != nil {
			if d.Pattern != "" {
				k.SubjectKind, k.Subject = SubjectSHMPattern, d.Pattern
			} else {
				k.SubjectKind, k.Subject = SubjectSHMName, d.SHMName
			}
		}
	case event.EventElfRpath:
		k.SubjectKind = SubjectRpath
		k.Subject = canonFileHash(evt.ExeHash)
	case event.EventPtraceInject:
		k.SubjectKind = SubjectPtrace
		k.Subject = canonFileHash(evt.ExeHash)
	}
	return k
}

func libraryValue(hash, path string) string {
	if hash != "" {
		return canonFileHash(hash)
	}
	return path
}

// EventTypesFor returns the event types a key covers. BPF keys cover
// all three BPF event types; other keys cover one.
func EventTypesFor(k event.LearnedKey) []event.EventType {
	switch k.SubjectKind {
	case SubjectBPFTag, SubjectBPFName:
		return []event.EventType{event.EventBPFLoad, event.EventBPFAttach, event.EventBPFInventory}
	case SubjectLDPreload, SubjectLDAudit, SubjectLDLibraryPath, SubjectLDDebug, SubjectScanTruncated:
		return []event.EventType{event.EventExecInjection}
	case SubjectDlopen:
		return []event.EventType{event.EventDlopen}
	case SubjectLibReplace:
		return []event.EventType{event.EventLibIntegrity}
	case SubjectLinkerConfig:
		return []event.EventType{event.EventLinkerConfig}
	case SubjectSHMPattern, SubjectSHMName:
		return []event.EventType{event.EventSHMCreate}
	case SubjectRpath:
		return []event.EventType{event.EventElfRpath}
	case SubjectPtrace:
		return []event.EventType{event.EventPtraceInject}
	default:
		return nil
	}
}

// KeyHash is a fixed-length identifier of a key: the hex SHA-256 of its
// fields, each length-prefixed. The store indexes PENDING entries by it,
// since a path in the key can be longer than an index entry may be.
func KeyHash(k event.LearnedKey) string {
	var b strings.Builder
	for _, f := range []string{
		k.SubjectKind, k.Subject, k.ContentHash,
		strconv.FormatUint(uint64(k.ProgType), 10),
	} {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// Describe is a one-line description of a learned key, for the entry's
// description field.
func Describe(k event.LearnedKey, exePath string) string {
	var b strings.Builder
	b.WriteString("learned: ")
	switch k.SubjectKind {
	case SubjectBPFTag:
		fmt.Fprintf(&b, "BPF tag %s, prog type %d", k.Subject, k.ProgType)
	case SubjectBPFName:
		fmt.Fprintf(&b, "BPF program %q (no tag), prog type %d", k.Subject, k.ProgType)
	case SubjectLDPreload:
		fmt.Fprintf(&b, "LD_PRELOAD %s", k.Subject)
	case SubjectLDAudit:
		fmt.Fprintf(&b, "LD_AUDIT %s", k.Subject)
	case SubjectLDLibraryPath:
		fmt.Fprintf(&b, "LD_LIBRARY_PATH %s", k.Subject)
	case SubjectLDDebug:
		b.WriteString("LD_DEBUG")
	case SubjectScanTruncated:
		b.WriteString("truncated environment scan")
	case SubjectDlopen:
		fmt.Fprintf(&b, "dlopen %s", k.Subject)
	case SubjectLibReplace:
		fmt.Fprintf(&b, "library %s replaced", k.Subject)
		if k.ContentHash != "" {
			fmt.Fprintf(&b, " (%s)", k.ContentHash)
		}
	case SubjectLinkerConfig:
		fmt.Fprintf(&b, "linker config %s changed", k.Subject)
		if k.ContentHash != "" {
			fmt.Fprintf(&b, " (%s)", k.ContentHash)
		}
	case SubjectSHMPattern:
		fmt.Fprintf(&b, "shm pattern %s", k.Subject)
	case SubjectSHMName:
		fmt.Fprintf(&b, "shm name %s", k.Subject)
	case SubjectRpath:
		fmt.Fprintf(&b, "RPATH in binary %s", k.Subject)
	case SubjectPtrace:
		fmt.Fprintf(&b, "ptrace from binary %s", k.Subject)
	default:
		if k.Subject != "" {
			fmt.Fprintf(&b, "%s %s", k.SubjectKind, k.Subject)
		}
	}
	if exePath != "" {
		fmt.Fprintf(&b, " [%s]", exePath)
	}
	return b.String()
}
