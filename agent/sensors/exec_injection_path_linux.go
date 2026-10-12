//go:build linux

package sensors

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"

	"github.com/dlenrow/hookmon/pkg/event"
)

// reportExecInjection says whether one exec_injection record becomes an
// event. Only LD_LIBRARY_PATH is ever dropped: when every entry is a
// standard library directory or a directory only root can write, judged as
// the new process sees the filesystem. Anything the sensor cannot judge (a
// process gone from the mount namespace the exec happened in, a value cut
// short that /proc no longer has in full) is reported.
func reportExecInjection(raw *execInjectionEvent) bool {
	if nullTermStr(raw.EnvVarName[:]) != "LD_LIBRARY_PATH" {
		return true
	}
	value := nullTermStr(raw.EnvValue[:])
	if raw.Flags&envValueTruncated != 0 {
		full, ok := processEnvValue(raw.PID, "LD_LIBRARY_PATH")
		if !ok {
			return true
		}
		value = full
	}
	fs, done, ok := execFS(raw)
	if !ok {
		return true
	}
	defer done()
	binaryDir := ""
	if f := nullTermStr(raw.Filename[:]); filepath.IsAbs(f) {
		binaryDir = filepath.Dir(f)
	}
	risk, _ := searchPathRisk(fs, value, binaryDir)
	return !RiskBelow(risk, event.RpathRiskMedium)
}

// execFS returns the filesystem as the process that exec'd sees it: the
// bus's own when the exec happened in the bus's mount namespace, otherwise
// the root of that process, or of its parent if the kernel reported the two
// share it, while it is still in that namespace.
func execFS(raw *execInjectionEvent) (libFS, func(), bool) {
	if raw.MntNs != 0 && nsInode("/proc/self/ns/mnt") == uint64(raw.MntNs) {
		return hostFS{}, func() {}, true
	}
	pids := []uint32{raw.PID}
	if raw.Flags&envParentRoot != 0 {
		pids = append(pids, raw.PPID)
	}
	for _, pid := range pids {
		proc := "/proc/" + strconv.FormatUint(uint64(pid), 10)
		if raw.MntNs == 0 || nsInode(proc+"/ns/mnt") != uint64(raw.MntNs) {
			continue
		}
		if fs, err := openRootFS(proc + "/root"); err == nil {
			return fs, fs.close, true
		}
	}
	return nil, nil, false
}

// processEnvValue returns the value of name in pid's environment, read from
// /proc/<pid>/environ.
func processEnvValue(pid uint32, name string) (string, bool) {
	env, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/environ")
	if err != nil {
		return "", false
	}
	prefix := []byte(name + "=")
	for _, kv := range bytes.Split(env, []byte{0}) {
		if v, ok := bytes.CutPrefix(kv, prefix); ok {
			return string(v), true
		}
	}
	return "", false
}
