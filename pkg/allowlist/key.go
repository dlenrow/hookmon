package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Subject kinds of a LearnedKey.
const (
	SubjectBPFTag      = "bpf_tag"
	SubjectBPFName     = "bpf_name"
	SubjectLibraryHash = "library_hash"
	SubjectLibraryPath = "library_path"
	SubjectSHMPattern  = "shm_pattern"
	SubjectSHMName     = "shm_name"
	SubjectFilePath    = "file_path"
)

// KeyOf returns the learning-mode key of an event: its type, the acting
// binary's hash, what it acted on, and whether it ran in a container.
//
// The subject is, by event type:
//   - BPF_LOAD, BPF_ATTACH, BPF_INVENTORY: the program tag, plus the program
//     type (identical instructions of different types share a tag). When the
//     kernel gave no tag, the program name stands in.
//   - EXEC_INJECTION, DLOPEN: the library's hash, or its path when it has no
//     hash.
//   - LIB_INTEGRITY: the library path. LINKER_CONFIG: the file path.
//   - SHM_CREATE: the pattern the bus gave the segment name (bpftime,
//     bpf_related or unknown); the name itself only when there is no pattern.
//   - PTRACE_INJECT, ELF_RPATH: none; the exe hash identifies the binary.
func KeyOf(evt *event.HookEvent) event.LearnedKey {
	k := event.LearnedKey{
		EventType:   evt.EventType,
		ExeHash:     canonFileHash(evt.ExeHash),
		InContainer: evt.ContainerID != "",
	}
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
			k.SubjectKind, k.Subject = librarySubject(d.LibraryHash, d.LibraryPath)
		}
	case event.EventDlopen:
		if d := evt.DlopenDetail; d != nil {
			k.SubjectKind, k.Subject = librarySubject(d.LibraryHash, d.LibraryPath)
		}
	case event.EventLibIntegrity:
		if d := evt.LibIntegrityDetail; d != nil {
			k.SubjectKind, k.Subject = SubjectLibraryPath, d.LibraryPath
		}
	case event.EventLinkerConfig:
		if d := evt.LinkerConfigDetail; d != nil {
			k.SubjectKind, k.Subject = SubjectFilePath, d.FilePath
		}
	case event.EventSHMCreate:
		if d := evt.SHMDetail; d != nil {
			// The bus's pattern for the name, not the name: programs such as
			// Chromium name every segment randomly, which made each one a
			// candidate of its own (566 in 5 minutes on an idle host).
			if d.Pattern != "" {
				k.SubjectKind, k.Subject = SubjectSHMPattern, d.Pattern
			} else {
				k.SubjectKind, k.Subject = SubjectSHMName, d.SHMName
			}
		}
	}
	return k
}

func librarySubject(hash, path string) (string, string) {
	switch {
	case hash != "":
		return SubjectLibraryHash, canonFileHash(hash)
	case path != "":
		return SubjectLibraryPath, path
	}
	return "", ""
}

// KeyHash is a fixed-length identifier of a key: the hex SHA-256 of its
// fields, each length-prefixed. The store indexes PENDING entries by it,
// since a path in the key can be longer than an index entry may be.
func KeyHash(k event.LearnedKey) string {
	var b strings.Builder
	for _, f := range []string{
		string(k.EventType), k.ExeHash, k.SubjectKind, k.Subject,
		strconv.FormatUint(uint64(k.ProgType), 10), strconv.FormatBool(k.InContainer),
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
	b.WriteString(string(k.EventType))
	switch {
	case exePath != "":
		fmt.Fprintf(&b, " by %s", exePath)
	case k.ExeHash != "":
		fmt.Fprintf(&b, " by %s", k.ExeHash)
	}
	if k.InContainer {
		b.WriteString(" in a container")
	}
	switch k.SubjectKind {
	case SubjectBPFTag:
		fmt.Fprintf(&b, ": BPF tag %s, prog type %d", k.Subject, k.ProgType)
	case SubjectBPFName:
		fmt.Fprintf(&b, ": BPF program %q (no tag), prog type %d", k.Subject, k.ProgType)
	case "":
	default:
		fmt.Fprintf(&b, ": %s %s", strings.ReplaceAll(k.SubjectKind, "_", " "), k.Subject)
	}
	return b.String()
}
