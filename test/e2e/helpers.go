//go:build linux

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// BusProcess manages a hookmon-bus running in console mode for testing.
type BusProcess struct {
	cmd    *exec.Cmd
	events chan *event.HookEvent
	lines  chan string
	done   chan struct{}
}

func lokiURL() string {
	return os.Getenv("HOOKMON_LOKI_URL")
}

func statusPort() string {
	return os.Getenv("HOOKMON_STATUS_PORT")
}

// StartBus launches hookmon-bus --console and captures its JSON output.
func StartBus(busBin string) (*BusProcess, error) {
	args := []string{"--console"}
	if u := lokiURL(); u != "" {
		args = append(args, "--loki-url", u)
	}
	if p := statusPort(); p != "" {
		args = append(args, "--status-port", p)
	}
	cmd := exec.Command(busBin, args...)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	bp := &BusProcess{
		cmd:    cmd,
		events: make(chan *event.HookEvent, 10000),
		lines:  make(chan string, 10000),
		done:   make(chan struct{}),
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start bus: %w", err)
	}

	// Parse JSON events from stdout
	go func() {
		defer close(bp.done)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		var jsonBuf strings.Builder
		braceDepth := 0

		for scanner.Scan() {
			line := scanner.Text()
			bp.lines <- line

			trimmed := strings.TrimSpace(line)
			if trimmed == "{" || strings.HasPrefix(trimmed, "{") {
				if braceDepth == 0 {
					jsonBuf.Reset()
				}
			}

			for _, ch := range trimmed {
				if ch == '{' {
					braceDepth++
				} else if ch == '}' {
					braceDepth--
				}
			}
			jsonBuf.WriteString(line)
			jsonBuf.WriteByte('\n')

			if braceDepth == 0 && jsonBuf.Len() > 2 {
				var evt event.HookEvent
				if err := json.Unmarshal([]byte(jsonBuf.String()), &evt); err == nil {
					bp.events <- &evt
				}
				jsonBuf.Reset()
			}
		}
	}()

	// Give bus time to start sensors
	time.Sleep(2 * time.Second)
	return bp, nil
}

// Stop terminates the bus process.
func (bp *BusProcess) Stop() error {
	if bp.cmd.Process != nil {
		bp.cmd.Process.Signal(os.Interrupt)
		time.Sleep(500 * time.Millisecond)
		bp.cmd.Process.Kill()
	}
	return bp.cmd.Wait()
}

// WaitForEvent waits for an event matching the filter within the timeout.
func (bp *BusProcess) WaitForEvent(filter func(*event.HookEvent) bool, timeout time.Duration) (*event.HookEvent, error) {
	deadline := time.After(timeout)
	for {
		select {
		case evt := <-bp.events:
			if filter(evt) {
				return evt, nil
			}
		case <-deadline:
			return nil, fmt.Errorf("timeout waiting for matching event after %v", timeout)
		}
	}
}

// LoadCanary runs the BPF canary loader with sudo and returns when it exits.
func LoadCanary(loaderBin, bpfObj, tpGroup, tpName, progName string) error {
	cmd := exec.Command("sudo", loaderBin, bpfObj, tpGroup, tpName, progName)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunCanaryBinary executes a canary binary with optional args (with sudo).
// Output goes to stderr to avoid corrupting the bus's JSON stdout stream.
func RunCanaryBinary(bin string, args ...string) error {
	allArgs := append([]string{bin}, args...)
	cmd := exec.Command("sudo", allArgs...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunShellCanary executes a shell canary script with optional args (with sudo).
func RunShellCanary(script string, args ...string) error {
	allArgs := append([]string{"bash", script}, args...)
	cmd := exec.Command("sudo", allArgs...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunExecWithPreload executes a binary with LD_PRELOAD set to trigger both
// the exec_injection sensor (which sees the LD_PRELOAD) and the elf_rpath
// audit (which runs on the enriched ExePath).
func RunExecWithPreload(binary, libPath string) error {
	cmd := exec.Command("sudo", "env", "LD_PRELOAD="+libPath, binary)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunBpftimeSim executes the bpftime attack simulator.
func RunBpftimeSim(simBin, libPath, targetBin string) error {
	cmd := exec.Command("sudo", simBin, libPath, targetBin)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// EvaluateAgainstAllowlist evaluates an event against allowlist entries
// using the same logic as the server policy engine.
func EvaluateAgainstAllowlist(evt *event.HookEvent, entries []*event.AllowlistEntry) *event.PolicyResult {
	for _, entry := range entries {
		if matchesEntry(entry, evt) {
			return &event.PolicyResult{
				Action:         entry.Action,
				MatchedEntryID: entry.ID,
				Reason:         fmt.Sprintf("matched allowlist entry: %s", entry.Description),
			}
		}
	}
	return &event.PolicyResult{
		Action: event.ActionAlert,
		Reason: "no matching allowlist entry",
	}
}

// matchesEntry is a simplified version of policy.Matches for testing.
func matchesEntry(entry *event.AllowlistEntry, evt *event.HookEvent) bool {
	if !entry.Enabled {
		return false
	}
	if entry.Expires != nil && entry.Expires.Before(time.Now()) {
		return false
	}
	if len(entry.EventTypes) > 0 {
		found := false
		for _, et := range entry.EventTypes {
			if et == evt.EventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if entry.ExeHash != "" && evt.ExeHash != entry.ExeHash {
		return false
	}
	if entry.ProgHash != "" {
		if evt.BPFDetail == nil || evt.BPFDetail.ProgHash != entry.ProgHash {
			return false
		}
	}
	if entry.ProgName != "" {
		if evt.BPFDetail == nil || evt.BPFDetail.ProgName != entry.ProgName {
			return false
		}
	}
	if entry.LibraryPath != "" {
		switch evt.EventType {
		case event.EventExecInjection:
			if evt.ExecInjectionDetail == nil || !strings.Contains(evt.ExecInjectionDetail.LibraryPath, entry.LibraryPath) {
				return false
			}
		case event.EventSHMCreate:
			if evt.SHMDetail == nil || !strings.Contains(evt.SHMDetail.SHMName, entry.LibraryPath) {
				return false
			}
		case event.EventDlopen:
			if evt.DlopenDetail == nil || !strings.Contains(evt.DlopenDetail.LibraryPath, entry.LibraryPath) {
				return false
			}
		default:
			return false
		}
	}
	if entry.LibraryHash != "" {
		if evt.ExecInjectionDetail == nil || evt.ExecInjectionDetail.LibraryHash != entry.LibraryHash {
			return false
		}
	}
	return true
}
