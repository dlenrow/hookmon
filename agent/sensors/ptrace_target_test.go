package sensors

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// shmPtrFakeTask adds /proc/<pid>/task/<tid> to a fake procfs, with the
// process in PID namespace ns and nspid as the thread's NSpid line.
func shmPtrFakeTask(t *testing.T, root string, pid, tid int, ns uint64, nspid, comm string) {
	t.Helper()
	pdir := filepath.Join(root, fmt.Sprint(pid))
	tdir := filepath.Join(pdir, "task", fmt.Sprint(tid))
	if err := os.MkdirAll(tdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pdir, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(pdir, "ns", "pid")
	if _, err := os.Lstat(link); err != nil {
		if err := os.Symlink(fmt.Sprintf("pid:[%d]", ns), link); err != nil {
			t.Fatal(err)
		}
	}
	status := fmt.Sprintf("Name:\t%s\nTgid:\t%d\nNSpid:\t%s\nPPid:\t1\n", comm, pid, nspid)
	for path, content := range map[string]string{
		filepath.Join(tdir, "status"): status,
		filepath.Join(tdir, "comm"):   comm + "\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// /proc/<tid>/comm, as the kernel serves it for any thread ID.
	if tid == pid {
		if err := os.WriteFile(filepath.Join(pdir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestShmPtrPtraceTargetComm(t *testing.T) {
	const hostNS, containerA, containerB = 4026531836, 4026532001, 4026532002
	root := t.TempDir()
	shmPtrFakeTask(t, root, 2, 2, hostNS, "2", "kthreadd")
	shmPtrFakeTask(t, root, 900, 900, hostNS, "900", "gdb")
	// Container A: pid 1 is 5000 on the host, its second thread 5002 is 2.
	shmPtrFakeTask(t, root, 5000, 5000, containerA, "5000\t1", "app")
	shmPtrFakeTask(t, root, 5000, 5002, containerA, "5002\t2", "app-worker")
	// Container B also has a thread 2.
	shmPtrFakeTask(t, root, 6000, 6001, containerB, "6001\t2", "other")

	tests := []struct {
		name     string
		callerNS uint64
		target   uint32
		want     string
	}{
		{"caller in the bus's namespace", hostNS, 900, "gdb"},
		{"host caller, pid 2 is the host's", hostNS, 2, "kthreadd"},
		{"container caller, pid 2 is its own", containerA, 2, "app-worker"},
		{"other container, same pid", containerB, 2, "other"},
		{"no such target in the namespace", containerA, 7, ""},
		{"no such host pid", hostNS, 12345, ""},
		{"namespace unknown", 0, 2, ""},
		{"pid 0", hostNS, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ptraceTargetComm(root, hostNS, tt.callerNS, tt.target); got != tt.want {
				t.Errorf("ptraceTargetComm(ns %d, %d) = %q, want %q", tt.callerNS, tt.target, got, tt.want)
			}
		})
	}
}
