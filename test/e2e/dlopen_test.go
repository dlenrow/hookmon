//go:build linux && e2e

package e2e

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// dlopen_monitor tests from fix plan step 4: a container's own libc is
// covered, and repeats of (binary, library) are reported once.

// dlopenWImage is debian:bookworm-slim (glibc 2.36), pinned by index digest.
// dlopen_canary is built against the host's glibc and runs inside it on the
// container's own libc, so the host needs glibc 2.36 or older for its
// symbol versions to resolve; Ubuntu 22.10 has 2.36.
const dlopenWImage = "debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587"

func dlopenWDocker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func dlopenWFileSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(b))
}

// dlopenWLibc returns the "dev inode" of the libc.so.6 that pid has mapped,
// or "" if it has none yet.
func dlopenWLibc(pid string) string {
	f, err := os.Open("/proc/" + pid + "/maps")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 6 && strings.HasSuffix(fields[5], "/libc.so.6") {
			return fields[3] + " " + fields[4]
		}
	}
	return ""
}

// TestDlopenW_ContainerLibc: a dlopen inside a container that has its own
// glibc is detected. The container is started before the bus, so the bus's
// startup scan finds the container's libc in /proc/<pid>/maps.
func TestDlopenW_ContainerLibc(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "image", "inspect", dlopenWImage).Run(); err != nil {
		t.Logf("pulling %s", dlopenWImage)
		dlopenWDocker(t, "pull", "-q", dlopenWImage)
		// Remove the image only if this test pulled it.
		t.Cleanup(func() {
			if out, err := exec.Command("docker", "rmi", dlopenWImage).CombinedOutput(); err != nil {
				t.Errorf("docker rmi: %v\n%s", err, out)
			}
		})
	}

	name := fmt.Sprintf("hookmon-e2e-dlopen-%d", os.Getpid())
	exec.Command("docker", "rm", "-f", name).Run()
	dlopenWDocker(t, "run", "-d", "--name", name, "--network", "none",
		"-v", canaryBinDir()+":/canary:ro", dlopenWImage, "sleep", "infinity")
	t.Cleanup(func() {
		if out, err := exec.Command("docker", "rm", "-f", name).CombinedOutput(); err != nil {
			t.Errorf("docker rm: %v\n%s", err, out)
		}
	})
	pid := dlopenWDocker(t, "inspect", "-f", "{{.State.Pid}}", name)

	var ctrLibc string
	for i := 0; i < 50 && ctrLibc == ""; i++ {
		if ctrLibc = dlopenWLibc(pid); ctrLibc == "" {
			time.Sleep(100 * time.Millisecond)
		}
	}
	hostLibc := dlopenWLibc("1")
	if ctrLibc == "" || hostLibc == "" {
		t.Fatalf("libc not found in maps: container pid %s %q, host pid 1 %q", pid, ctrLibc, hostLibc)
	}
	if ctrLibc == hostLibc {
		t.Fatalf("the container maps the host's libc (%s); the test needs a second libc", hostLibc)
	}
	t.Logf("host libc %s, container libc %s (pid %s)", hostLibc, ctrLibc, pid)

	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	const ctrLib = "/canary/libfake_hook.so"
	cmd := exec.Command("docker", "exec", name, "/canary/dlopen_canary", ctrLib)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("dlopen_canary in the container: %v", err)
	}

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventDlopen && e.DlopenDetail != nil &&
			e.DlopenDetail.LibraryPath == ctrLib
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect DLOPEN of %s inside the container: %v", ctrLib, err)
	}
	t.Logf("PASS: DLOPEN in container detected: lib=%s hash=%s pid=%d exe=%s container=%s",
		evt.DlopenDetail.LibraryPath, evt.DlopenDetail.LibraryHash, evt.PID, evt.ExePath, evt.ContainerID)

	// The library path is the container's; the bus hashes it through the
	// container's root, which here is the bind-mounted canary directory.
	if want := dlopenWFileSHA(t, canaryBinDir()+"/libfake_hook.so"); evt.DlopenDetail.LibraryHash != want {
		t.Errorf("LibraryHash = %q, want %q", evt.DlopenDetail.LibraryHash, want)
	}
	if want := dlopenWFileSHA(t, canaryBinDir()+"/dlopen_canary"); evt.ExeHash != want {
		t.Errorf("ExeHash = %q, want %q", evt.ExeHash, want)
	}
}

// TestDlopenW_Dedupe: the same binary loading the same library twice is
// reported once; a different library path from the same binary still is.
func TestDlopenW_Dedupe(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	canary := canaryBinDir() + "/dlopen_canary"
	lib := canaryBinDir() + "/libfake_hook.so"
	// The same file under another path string: a different key.
	marker := canaryBinDir() + "/./libfake_hook.so"
	for _, p := range []string{lib, lib, marker} {
		if err := RunCanaryBinary(canary, p); err != nil {
			t.Fatalf("dlopen_canary %s: %v", p, err)
		}
	}

	isDlopen := func(path string) func(*event.HookEvent) bool {
		return func(e *event.HookEvent) bool {
			return e.EventType == event.EventDlopen && e.DlopenDetail != nil && e.DlopenDetail.LibraryPath == path
		}
	}
	first, err := bus.WaitForEvent(isDlopen(lib), 15*time.Second)
	if err != nil {
		t.Fatalf("first dlopen not reported: %v", err)
	}
	if first.ExeHash == "" {
		t.Fatal("first event has no exe hash; the dedupe key needs one")
	}
	second, err := bus.WaitForEvent(isDlopen(marker), 15*time.Second)
	if err != nil {
		t.Fatalf("dlopen of %s not reported: %v", marker, err)
	}
	if second.ExeHash != first.ExeHash {
		t.Errorf("exe hash differs between runs of one binary: %s, %s", first.ExeHash, second.ExeHash)
	}
	// Events from one sensor arrive in order, so the repeat, had it been
	// sent, would already have been read before the marker.
	if dup, err := bus.WaitForEvent(isDlopen(lib), 2*time.Second); err == nil {
		t.Errorf("repeat of (exe, %s) was reported: pid %d", lib, dup.PID)
	}
}
