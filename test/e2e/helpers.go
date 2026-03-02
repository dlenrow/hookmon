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

// AgentProcess manages a hookmon-agent running in console mode for testing.
type AgentProcess struct {
	cmd    *exec.Cmd
	events chan *event.HookEvent
	lines  chan string
	done   chan struct{}
}

func lokiURL() string {
	return os.Getenv("HOOKMON_LOKI_URL")
}

func prometheusPort() string {
	return os.Getenv("HOOKMON_PROMETHEUS_PORT")
}

// StartAgent launches hookmon-agent --console and captures its JSON output.
// Set HOOKMON_LOKI_URL and HOOKMON_PROMETHEUS_PORT env vars to enable observability.
func StartAgent(agentBin string) (*AgentProcess, error) {
	args := []string{"--console"}
	if u := lokiURL(); u != "" {
		args = append(args, "--loki-url", u)
	}
	if p := prometheusPort(); p != "" {
		args = append(args, "--prometheus-port", p)
	}
	cmd := exec.Command(agentBin, args...)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	ap := &AgentProcess{
		cmd:    cmd,
		events: make(chan *event.HookEvent, 100),
		lines:  make(chan string, 1000),
		done:   make(chan struct{}),
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start agent: %w", err)
	}

	// Parse JSON events from stdout
	go func() {
		defer close(ap.done)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1MB buffer for large JSON
		var jsonBuf strings.Builder
		braceDepth := 0

		for scanner.Scan() {
			line := scanner.Text()
			ap.lines <- line

			// Accumulate JSON object lines (pretty-printed JSON spans multiple lines)
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
					ap.events <- &evt
				}
				jsonBuf.Reset()
			}
		}
	}()

	// Give agent time to start sensors
	time.Sleep(2 * time.Second)
	return ap, nil
}

// Stop terminates the agent process.
func (ap *AgentProcess) Stop() error {
	if ap.cmd.Process != nil {
		ap.cmd.Process.Signal(os.Interrupt)
		time.Sleep(500 * time.Millisecond)
		ap.cmd.Process.Kill()
	}
	return ap.cmd.Wait()
}

// WaitForEvent waits for an event matching the filter function within the timeout.
func (ap *AgentProcess) WaitForEvent(filter func(*event.HookEvent) bool, timeout time.Duration) (*event.HookEvent, error) {
	deadline := time.After(timeout)
	for {
		select {
		case evt := <-ap.events:
			if filter(evt) {
				return evt, nil
			}
		case <-deadline:
			return nil, fmt.Errorf("timeout waiting for matching event after %v", timeout)
		}
	}
}

// LoadCanary runs the canary loader and returns when it exits.
func LoadCanary(loaderBin, bpfObj, tpGroup, tpName, progName string) error {
	cmd := exec.Command("sudo", loaderBin, bpfObj, tpGroup, tpName, progName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// LoadCanaryAsync runs the canary loader in the background and returns immediately.
func LoadCanaryAsync(loaderBin, bpfObj, tpGroup, tpName, progName string) (*exec.Cmd, error) {
	cmd := exec.Command("sudo", loaderBin, bpfObj, tpGroup, tpName, progName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// EvaluateAgainstAllowlist evaluates an event against a set of allowlist entries
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
	return true
}
