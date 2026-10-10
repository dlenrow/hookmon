//go:build linux

package enrichment

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/pkg/event"
)

// enrichNoSuchPID is above any pid_max, so /proc/<enrichNoSuchPID> never
// exists: the process has already exited.
const enrichNoSuchPID = 5000000

// enrichChildEnv, when set, makes the test binary act as the "container"
// process for TestEnrichContainerExeHashedThroughProcRoot. Its value is the
// directory to use as the container's root.
const enrichChildEnv = "HOOKMON_ENRICH_TEST_ROOT"

// enrichSetupFailed is the child's exit status when the kernel or policy
// refuses the namespace setup; the test is skipped then.
const enrichSetupFailed = 3

func init() {
	if root := os.Getenv(enrichChildEnv); root != "" {
		enrichPivotAndExec(root)
	}
}

// enrichPivotAndExec runs in a child started in new user and mount
// namespaces. Like a container runtime, it makes root the root of its mount
// namespace with pivot_root and detaches the old root, then execs /bin/sh
// inside it. The host's library directories are bind-mounted in so that
// /bin/sh, a copy of the host's sleep, can run.
func enrichPivotAndExec(root string) {
	fail := func(what string, err error) {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(enrichSetupFailed)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		fail("make / private", err)
	}
	for _, name := range []string{"usr", "lib", "lib64", "lib32", "libx32"} {
		fi, err := os.Lstat("/" + name)
		if err != nil {
			continue
		}
		dst := filepath.Join(root, name)
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink("/" + name)
			if err != nil {
				fail("readlink /"+name, err)
			}
			if err := os.Symlink(target, dst); err != nil {
				fail("symlink "+dst, err)
			}
		case fi.IsDir():
			if err := os.Mkdir(dst, 0o755); err != nil {
				fail("mkdir "+dst, err)
			}
			if err := unix.Mount("/"+name, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
				fail("bind /"+name, err)
			}
		}
	}
	if err := unix.Mount(root, root, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		fail("bind new root", err)
	}
	if err := unix.PivotRoot(root, filepath.Join(root, ".old")); err != nil {
		fail("pivot_root", err)
	}
	if err := unix.Chdir("/"); err != nil {
		fail("chdir /", err)
	}
	if err := unix.Unmount("/.old", unix.MNT_DETACH); err != nil {
		fail("detach old root", err)
	}
	err := unix.Exec("/bin/sh", []string{"/bin/sh", "300"}, nil)
	fmt.Fprintf(os.Stderr, "exec /bin/sh: %v\n", err)
	os.Exit(1)
}

func enrichCopyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// A process in another mount namespace reports its exe path as it sees it,
// and that path names a different file on the host. The hash must be of
// the container's file, read through /proc/<pid>/root, not of the host's.
func TestEnrichContainerExeHashedThroughProcRoot(t *testing.T) {
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	root := t.TempDir()
	for _, d := range []string{"bin", ".old"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	containerSh := filepath.Join(root, "bin", "sh")
	enrichCopyFile(t, sleepBin, containerSh, 0o755)
	want := SHA256File(containerSh)
	hostSh := SHA256File("/bin/sh")
	if want == "" || want == hostSh {
		t.Fatalf("test setup: container /bin/sh hash %q must differ from the host's %q", want, hostSh)
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd := exec.Command(self)
	cmd.Env = []string{enrichChildEnv + "=" + root}
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		Pdeathsig:   syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot create user and mount namespaces here: %v", err)
	}
	// done is closed once Wait returns, so both the loop below and the
	// cleanup can wait on it; a one-shot channel value would leave the
	// cleanup blocked forever after the loop took it.
	var waitErr error
	done := make(chan struct{})
	go func() { waitErr = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-done
	})

	procDir := fmt.Sprintf("/proc/%d", cmd.Process.Pid)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if p, _ := os.Readlink(procDir + "/exe"); p == "/bin/sh" {
			break
		}
		select {
		case <-done:
			var ee *exec.ExitError
			if errors.As(waitErr, &ee) && ee.ExitCode() == enrichSetupFailed {
				t.Skipf("namespace setup refused here: %s", stderr.String())
			}
			t.Fatalf("child exited before exec: %v: %s", waitErr, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("child never exec'd /bin/sh: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	evt := &event.HookEvent{PID: uint32(cmd.Process.Pid)}
	NewEnricher().Enrich(evt)
	if evt.ExePath != "/bin/sh" {
		t.Errorf("ExePath = %q, want /bin/sh, the path inside the container", evt.ExePath)
	}
	switch evt.ExeHash {
	case want:
	case hostSh:
		t.Errorf("ExeHash is the host's /bin/sh, not the container's")
	default:
		t.Errorf("ExeHash = %q, want %q (the container's /bin/sh)", evt.ExeHash, want)
	}
}

// openInRoot keeps absolute symlinks and ".." inside the root, so a
// symlink planted in a container cannot point the bus at a host file.
func TestEnrichOpenInRootStaysInRoot(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"bin", "etc"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "hostname"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(root, "bin", "abs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../../../../etc/hostname", filepath.Join(root, "bin", "rel")); err != nil {
		t.Fatal(err)
	}
	rootFile, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rootFile.Close()

	for _, p := range []string{"/bin/abs", "/bin/rel", "/../../etc/hostname"} {
		f, err := openInRoot(rootFile, root, p, os.O_RDONLY)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		data, _ := io.ReadAll(f)
		f.Close()
		if string(data) != "inside" {
			t.Errorf("%s resolved outside the root: read %q", p, data)
		}
	}
}

// A process in the bus's own mount namespace: the path is a host path.
// The second lookup of the same binary is a cache hit.
func TestEnrichOwnProcess(t *testing.T) {
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEnricher()
	enrichOldEnough(e.hashes)
	evt := &event.HookEvent{PID: uint32(os.Getpid())}
	e.Enrich(evt)
	if evt.ExePath != exe {
		t.Errorf("ExePath = %q, want %q", evt.ExePath, exe)
	}
	if want := SHA256File(exe); evt.ExeHash != want {
		t.Errorf("ExeHash = %q, want %q", evt.ExeHash, want)
	}
	if evt.Cmdline == "" {
		t.Error("Cmdline is empty")
	}
	e.Enrich(&event.HookEvent{PID: uint32(os.Getpid())})
	if e.hashes.hits != 1 {
		t.Errorf("second event for the same binary: %d cache hits, want 1", e.hashes.hits)
	}
}

// A path and hash the sensor set are kept. Once the process is gone, the
// namespace its path belongs to is unknown, so nothing is hashed.
func TestEnrichKeepsSensorFieldsAndSkipsExitedProcess(t *testing.T) {
	e := NewEnricher()
	evt := &event.HookEvent{PID: enrichNoSuchPID, ExePath: "/bin/sh"}
	e.Enrich(evt)
	if evt.ExePath != "/bin/sh" || evt.ExeHash != "" {
		t.Errorf("exited process: ExePath %q ExeHash %q, want /bin/sh and no hash", evt.ExePath, evt.ExeHash)
	}

	evt = &event.HookEvent{PID: uint32(os.Getpid()), ExePath: "/sensor/path", ExeHash: "sha256:sensor"}
	e.Enrich(evt)
	if evt.ExePath != "/sensor/path" || evt.ExeHash != "sha256:sensor" {
		t.Errorf("sensor fields overwritten: ExePath %q ExeHash %q", evt.ExePath, evt.ExeHash)
	}
}
