package sensors

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ptraceTargetComm returns the comm of the thread a ptrace() call named, or
// "" if it can't be found. target is a thread ID in the caller's PID
// namespace, callerNS that namespace's inode number, and selfNS the bus's own;
// procRoot is normally "/proc".
//
// A caller in the bus's namespace names targets by the IDs /proc uses. For a
// caller in another namespace (a container), the target is the thread in
// that namespace whose innermost ID (the last NSpid entry) is target. A
// target in a namespace nested below the caller's is not found.
//
// The read happens after the call, so a target that has already exited is
// not found. ATTACH stops the target and the other requests need it stopped,
// so in practice it is still there.
func ptraceTargetComm(procRoot string, selfNS, callerNS uint64, target uint32) string {
	if target == 0 || callerNS == 0 {
		return ""
	}
	if callerNS == selfNS {
		return ptraceReadComm(filepath.Join(procRoot, strconv.FormatUint(uint64(target), 10), "comm"))
	}
	return ptraceCommInPidNS(procRoot, callerNS, target)
}

// ptraceCommInPidNS scans procRoot for the thread in PID namespace ns whose
// ID in that namespace is target.
func ptraceCommInPidNS(procRoot string, ns uint64, target uint32) string {
	nsLink := fmt.Sprintf("pid:[%d]", ns)
	procs, err := os.ReadDir(procRoot)
	if err != nil {
		return ""
	}
	for _, p := range procs {
		if _, err := strconv.ParseUint(p.Name(), 10, 32); err != nil {
			continue
		}
		dir := filepath.Join(procRoot, p.Name())
		if l, err := os.Readlink(filepath.Join(dir, "ns", "pid")); err != nil || l != nsLink {
			continue
		}
		tasks, err := os.ReadDir(filepath.Join(dir, "task"))
		if err != nil {
			continue
		}
		for _, t := range tasks {
			tdir := filepath.Join(dir, "task", t.Name())
			if id, ok := ptraceInnermostNSpid(filepath.Join(tdir, "status")); ok && id == target {
				return ptraceReadComm(filepath.Join(tdir, "comm"))
			}
		}
	}
	return ""
}

// ptraceInnermostNSpid returns the last ID on the NSpid line of a status
// file: the thread's ID in its own PID namespace.
func ptraceInnermostNSpid(statusPath string) (uint32, bool) {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0, false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "NSpid:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			return 0, false
		}
		id, err := strconv.ParseUint(f[len(f)-1], 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(id), true
	}
	return 0, false
}

func ptraceReadComm(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(string(data), "\n")
}
