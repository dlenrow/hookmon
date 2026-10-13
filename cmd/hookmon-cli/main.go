package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dlenrow/hookmon/pkg/version"
)

func main() {
	serverURL := flag.String("server", "https://localhost:8443", "hookmon-server URL")
	token := flag.String("token", "", "API authentication token")
	caFile := flag.String("ca-file", os.Getenv("HOOKMON_CA_FILE"), "CA certificate that signed the server's certificate (default $HOOKMON_CA_FILE; system roots if empty)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	client, err := newHTTPClient(*caFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	cli := &CLI{
		baseURL: strings.TrimRight(*serverURL, "/"),
		token:   *token,
		client:  client,
		out:     os.Stdout,
	}

	if err := cli.run(args); err != nil {
		if errors.Is(err, errUsage) {
			printUsage()
		} else {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(1)
	}
}

// errUsage is returned for an unknown command.
var errUsage = errors.New("usage")

// run dispatches one command line (without the global flags).
func (c *CLI) run(args []string) error {
	sub := func(i int) string {
		if len(args) > i {
			return args[i]
		}
		return ""
	}
	switch args[0] {
	case "events":
		return c.listEvents(args[1:])
	case "hosts":
		return c.listHosts()
	case "policies":
		switch sub(1) {
		case "":
			return c.listPolicies("")
		case "pending":
			return c.listPending(args[2:])
		case "create":
			return c.createPolicy(os.Stdin)
		case "delete":
			if sub(2) == "" {
				return fmt.Errorf("usage: hookmon-cli policies delete <id>")
			}
			return c.deletePolicy(args[2])
		case "approve", "reject":
			return c.decide(args[1], args[2:])
		}
		return fmt.Errorf("unknown policies command %q", sub(1))
	case "learning":
		switch sub(1) {
		case "", "status":
			return c.getAndPrint(c.baseURL + "/api/v1/learning")
		case "start":
			return c.startLearning(args[2:])
		case "stop":
			return c.stopLearning(args[2:])
		}
		return fmt.Errorf("unknown learning command %q", sub(1))
	case "health":
		return c.health()
	case "smoketest":
		switch sub(1) {
		case "check":
			return c.smoketestCheck(args[2:])
		case "cleanup":
			return c.smoketestCleanup()
		}
		return fmt.Errorf("unknown smoketest command %q (check or cleanup)", sub(1))
	}
	fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
	return errUsage
}

// newHTTPClient trusts caFile for the server's certificate when it is set,
// since the API is served over TLS with the HookMon CA (step 7b).
func newHTTPClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return &http.Client{}, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}, nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: hookmon-cli [flags] <command> [args]

Commands:
  events              List recent events
  events --limit N    List N most recent events
  hosts               List monitored hosts
  policies            List the allowlist entries in force (APPROVED, REJECTED)
  policies pending [--since TIME|DURATION] [--host HOST] [--type EVENT_TYPE]
                      List new hooks waiting for a decision (PENDING),
                      optionally first seen since a time (RFC 3339) or within
                      a duration (90m, 36h, 7d), seen on a host (ID or
                      hostname), or of one event type
  policies create     Create a policy (reads JSON from stdin)
  policies delete ID  Delete a policy
  policies approve ID... --fleet | --seen-hosts | --host HOST_ID
                      Allow new hooks from now on (action ALLOW): for every
                      host, for the hosts each was seen on, or for one host
                      (one ID only)
  policies reject ID... --fleet | --seen-hosts | --host HOST_ID
                      Deny new hooks: they alert every time they happen
                      again, and are not proposed again
  learning            Show learning windows
  learning start --fleet | --host HOST_ID  --for DURATION | --until TIME
                      Start a quiet period until a time (RFC 3339) or for a
                      duration (90m, 36h, 7d): first sightings are recorded
                      and shown, but not sent to alert connectors
  learning stop --fleet | --host HOST_ID
                      End the quiet period now; PENDING entries stay
  health              Check server health
  smoketest check --since TIME|DURATION [--host HOST ...]
                      Print a hook-type x host table of smoketest results
                      (new, denied, allowed, missing). Exits non-zero if any
                      cell is missing.
  smoketest cleanup   Delete allowlist entries whose exe path matches the
                      smoketest (any status)

Flags:
`)
	flag.PrintDefaults()
}

// CLI is the hookmon command-line client.
type CLI struct {
	baseURL string
	token   string
	client  *http.Client
	out     io.Writer
}

func (c *CLI) listEvents(args []string) error {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	limit := fs.Int("limit", 50, "max events to return")
	hostID := fs.String("host", "", "filter by host ID")
	eventType := fs.String("type", "", "filter by event type")
	fs.Parse(args)

	u := fmt.Sprintf("%s/api/v1/events?limit=%d", c.baseURL, *limit)
	if *hostID != "" {
		u += "&host_id=" + *hostID
	}
	if *eventType != "" {
		u += "&event_type=" + *eventType
	}

	return c.getAndPrint(u)
}

func (c *CLI) listHosts() error {
	return c.getAndPrint(c.baseURL + "/api/v1/hosts")
}

func (c *CLI) listPolicies(status string) error {
	u := c.baseURL + "/api/v1/policies"
	if status != "" {
		u += "?status=" + status
	}
	return c.getAndPrint(u)
}

func (c *CLI) createPolicy(in io.Reader) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	body, err := c.do(http.MethodPost, "/api/v1/policies", data, http.StatusCreated)
	if err != nil {
		return err
	}
	return c.prettyPrint(body)
}

func (c *CLI) deletePolicy(id string) error {
	if _, err := c.do(http.MethodDelete, "/api/v1/policies/"+url.PathEscape(id), nil, http.StatusNoContent); err != nil {
		return err
	}
	fmt.Fprintln(c.out, "Policy deleted.")
	return nil
}

// scopeFlags adds --fleet and --host to fs. The returned func gives the
// host ID ("" for the fleet), or an error unless exactly one was given.
func scopeFlags(fs *flag.FlagSet) func() (string, error) {
	fleet := fs.Bool("fleet", false, "every host")
	host := fs.String("host", "", "one host, by host ID")
	return func() (string, error) {
		if *fleet == (*host != "") {
			return "", errors.New("give exactly one of --fleet or --host HOST_ID")
		}
		return *host, nil
	}
}

// parseWithIDs parses flags given before, between or after positional IDs,
// and returns the IDs.
func parseWithIDs(fs *flag.FlagSet, args []string) ([]string, error) {
	var ids []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		ids = append(ids, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(ids) == 0 {
		return nil, errors.New("missing entry ID")
	}
	return ids, nil
}

// decide approves or rejects PENDING entries: one entry for the fleet or
// one host through its own endpoint, and anything else (several entries,
// or --seen-hosts) in one call to /policies/decide.
func (c *CLI) decide(verb string, args []string) error {
	usage := fmt.Sprintf("usage: hookmon-cli policies %s <id>... --fleet | --seen-hosts | --host HOST_ID", verb)
	fs := flag.NewFlagSet("policies "+verb, flag.ContinueOnError)
	fleet := fs.Bool("fleet", false, "every host")
	seenHosts := fs.Bool("seen-hosts", false, "the hosts each entry was seen on")
	host := fs.String("host", "", "one host, by host ID (one entry only)")
	ids, err := parseWithIDs(fs, args)
	if err != nil {
		return fmt.Errorf("policies %s: %w (%s)", verb, err, usage)
	}
	n := 0
	for _, set := range []bool{*fleet, *seenHosts, *host != ""} {
		if set {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("policies %s: give exactly one of --fleet, --seen-hosts or --host HOST_ID", verb)
	}
	if *host != "" && len(ids) != 1 {
		return fmt.Errorf("policies %s: --host takes exactly one entry ID", verb)
	}

	if len(ids) == 1 && !*seenHosts {
		req := map[string]string{"scope": "fleet"}
		if *host != "" {
			req = map[string]string{"scope": "host", "host_id": *host}
		}
		data, _ := json.Marshal(req)
		body, err := c.do(http.MethodPost, "/api/v1/policies/"+url.PathEscape(ids[0])+"/"+verb, data, http.StatusOK)
		if err != nil {
			return err
		}
		return c.prettyPrint(body)
	}

	scope := "fleet"
	if *seenHosts {
		scope = "seen_hosts"
	}
	data, _ := json.Marshal(map[string]any{"ids": ids, "decision": verb, "scope": scope})
	body, err := c.do(http.MethodPost, "/api/v1/policies/decide", data, http.StatusOK)
	if err != nil {
		return err
	}
	if err := c.prettyPrint(body); err != nil {
		return err
	}
	var resp struct {
		Results []struct {
			ID    string `json:"id"`
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	failed := 0
	for _, r := range resp.Results {
		if !r.OK {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("policies %s: %d of %d entries not decided", verb, failed, len(resp.Results))
	}
	return nil
}

// pendingEntry is the part of a PENDING entry listPending filters on.
type pendingEntry struct {
	Learned *struct {
		Key struct {
			EventType string `json:"event_type"`
		} `json:"key"`
		FirstSeen time.Time `json:"first_seen"`
		Hosts     []string  `json:"hosts"`
	} `json:"learned"`
}

// listPending lists the new hooks waiting for a decision, filtered here:
// first seen since a time or within a duration, seen on a host (ID or
// hostname), of one event type.
func (c *CLI) listPending(args []string) error {
	fs := flag.NewFlagSet("policies pending", flag.ContinueOnError)
	since := fs.String("since", "", "first seen at or after this time (RFC 3339) or within this duration (90m, 36h, 7d)")
	host := fs.String("host", "", "seen on this host: host ID or hostname")
	typ := fs.String("type", "", "event type, such as BPF_LOAD")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("policies pending: unexpected arguments: %v", fs.Args())
	}
	var from time.Time
	if *since != "" {
		t, err := parseSince(*since, time.Now())
		if err != nil {
			return fmt.Errorf("policies pending: --since: %w", err)
		}
		from = t
	}
	hostIDs := map[string]bool{}
	if *host != "" {
		hostIDs[*host] = true
		body, err := c.do(http.MethodGet, "/api/v1/hosts", nil, http.StatusOK)
		if err != nil {
			return err
		}
		var hosts []struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
		}
		if err := json.Unmarshal(body, &hosts); err != nil {
			return fmt.Errorf("read hosts: %w", err)
		}
		for _, h := range hosts {
			if strings.EqualFold(h.Hostname, *host) {
				hostIDs[h.ID] = true
			}
		}
	}

	body, err := c.do(http.MethodGet, "/api/v1/policies?status=PENDING", nil, http.StatusOK)
	if err != nil {
		return err
	}
	if *since == "" && *host == "" && *typ == "" {
		return c.prettyPrint(body)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("read entries: %w", err)
	}
	kept := []json.RawMessage{}
	for _, r := range raw {
		var e pendingEntry
		if err := json.Unmarshal(r, &e); err != nil || e.Learned == nil {
			continue
		}
		if !from.IsZero() && e.Learned.FirstSeen.Before(from) {
			continue
		}
		if *typ != "" && !strings.EqualFold(e.Learned.Key.EventType, *typ) {
			continue
		}
		if *host != "" {
			onHost := false
			for _, h := range e.Learned.Hosts {
				onHost = onHost || hostIDs[h]
			}
			if !onHost {
				continue
			}
		}
		kept = append(kept, r)
	}
	out, _ := json.Marshal(kept)
	return c.prettyPrint(out)
}

// parseSince reads --since: an RFC 3339 time, or a duration back from now
// (a Go duration such as 90m or 36h, or whole days such as 7d).
func parseSince(s string, now time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		var n int
		if _, err := fmt.Sscanf(days, "%d", &n); err == nil && n > 0 && fmt.Sprint(n) == days {
			return now.Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return time.Time{}, fmt.Errorf("%q is neither an RFC 3339 time nor a positive duration (90m, 36h, 7d)", s)
	}
	return now.Add(-d), nil
}

// learningPath is the API path of a learning window.
func learningPath(hostID string) string {
	if hostID == "" {
		return "/api/v1/learning/fleet"
	}
	return "/api/v1/learning/hosts/" + url.PathEscape(hostID)
}

func (c *CLI) startLearning(args []string) error {
	fs := flag.NewFlagSet("learning start", flag.ContinueOnError)
	scope := scopeFlags(fs)
	dur := fs.String("for", "", "how long: a Go duration (90m, 36h) or whole days (7d)")
	until := fs.String("until", "", "end time, RFC 3339 (2026-11-01T00:00:00Z)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("learning start: unexpected arguments: %v", fs.Args())
	}
	hostID, err := scope()
	if err != nil {
		return fmt.Errorf("learning start: %w", err)
	}
	req := map[string]string{}
	switch {
	case (*dur == "") == (*until == ""):
		return errors.New("learning start: give exactly one of --for DURATION or --until TIME")
	case *dur != "":
		req["duration"] = *dur
	default:
		if _, err := time.Parse(time.RFC3339, *until); err != nil {
			return fmt.Errorf("learning start: --until: %w", err)
		}
		req["ends_at"] = *until
	}
	data, _ := json.Marshal(req)
	body, err := c.do(http.MethodPut, learningPath(hostID), data, http.StatusOK)
	if err != nil {
		return err
	}
	return c.prettyPrint(body)
}

func (c *CLI) stopLearning(args []string) error {
	fs := flag.NewFlagSet("learning stop", flag.ContinueOnError)
	scope := scopeFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("learning stop: unexpected arguments: %v", fs.Args())
	}
	hostID, err := scope()
	if err != nil {
		return fmt.Errorf("learning stop: %w", err)
	}
	if _, err := c.do(http.MethodDelete, learningPath(hostID), nil, http.StatusNoContent); err != nil {
		return err
	}
	fmt.Fprintln(c.out, "Learning mode stopped.")
	return nil
}

func (c *CLI) health() error {
	return c.getAndPrint(c.baseURL + "/api/v1/health")
}

// do sends an authenticated request with an optional JSON body and returns
// the response body, or an error unless the status is want.
func (c *CLI) do(method, path string, data []byte, want int) ([]byte, error) {
	var rd io.Reader
	if data != nil {
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.baseURL+path, rd)
	if err != nil {
		return nil, err
	}
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return body, nil
}

func (c *CLI) getAndPrint(u string) error {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
	}
	return c.prettyPrint(body)
}

func (c *CLI) prettyPrint(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Fprintln(c.out, string(data))
		return nil
	}
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
