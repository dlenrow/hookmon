//go:build linux

package sensors

import (
	"bytes"
	"os"
	"testing"
)

// shmPtrNoSuchPID is above any pid_max, so /proc/<pid>/environ never exists.
const shmPtrNoSuchPID = 5000001

func shmPtrRecord(pid uint32, env []byte, total uint32) *shmEvent {
	raw := &shmEvent{PID: pid, EnvLen: uint32(len(env)), EnvTotal: total}
	copy(raw.Env[:], env)
	return raw
}

func TestShmPtrCreatorEnvCompleteCopy(t *testing.T) {
	env := []byte("A=1\x00BPFTIME_GLOBAL_SHM_NAME=x\x00")
	got := shmCreatorEnv(shmPtrRecord(shmPtrNoSuchPID, env, uint32(len(env))))
	if !bytes.Equal(got, env) {
		t.Fatalf("shmCreatorEnv = %q, want the BPF copy %q", got, env)
	}
}

func TestShmPtrCreatorEnvTruncatedReadsProc(t *testing.T) {
	// The copy holds only part of this process's environment; the rest must
	// come from /proc/self/environ.
	want, err := os.ReadFile("/proc/self/environ")
	if err != nil {
		t.Skipf("read /proc/self/environ: %v", err)
	}
	partial := []byte("PARTIAL=1\x00")
	got := shmCreatorEnv(shmPtrRecord(uint32(os.Getpid()), partial, uint32(len(want))+4096))
	if !bytes.Equal(got, want) {
		t.Fatalf("shmCreatorEnv did not read /proc/<pid>/environ for a truncated copy")
	}
}

func TestShmPtrCreatorEnvTruncatedCreatorGone(t *testing.T) {
	partial := []byte("A=1\x00BPFTIME_GLOBAL_SHM_NAME=inno")
	got := shmCreatorEnv(shmPtrRecord(shmPtrNoSuchPID, partial, 9000))
	if !bytes.Equal(got, partial) {
		t.Fatalf("shmCreatorEnv = %q, want the partial copy %q", got, partial)
	}
	if pattern, _ := classifySHM("inno", got); pattern != shmPatternUnknown {
		t.Fatalf("partial entry matched: pattern %s", pattern)
	}
}
