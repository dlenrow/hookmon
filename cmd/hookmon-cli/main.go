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
			return c.listPolicies("PENDING")
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
  policies pending    List learning-mode candidates (PENDING)
  policies create     Create a policy (reads JSON from stdin)
  policies delete ID  Delete a policy
  policies approve ID --fleet | --host HOST_ID
                      Approve a PENDING entry (action ALLOW) for every host,
                      or for one host
  policies reject ID --fleet | --host HOST_ID
                      Reject a PENDING entry (it keeps alerting and is not
                      proposed again) for every host, or for one host
  learning            Show learning windows
  learning start --fleet | --host HOST_ID  --for DURATION | --until TIME
                      Start learning mode until a time (RFC 3339) or for a
                      duration (90m, 36h, 7d)
  learning stop --fleet | --host HOST_ID
                      End learning mode now; PENDING entries stay
  health              Check server health

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

// parseWithID parses flags given before or after one positional ID.
func parseWithID(fs *flag.FlagSet, args []string) (string, error) {
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() == 0 {
		return "", errors.New("missing entry ID")
	}
	id := fs.Arg(0)
	if err := fs.Parse(fs.Args()[1:]); err != nil {
		return "", err
	}
	if fs.NArg() != 0 {
		return "", fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	return id, nil
}

// decide approves or rejects a PENDING entry.
func (c *CLI) decide(verb string, args []string) error {
	fs := flag.NewFlagSet("policies "+verb, flag.ContinueOnError)
	scope := scopeFlags(fs)
	id, err := parseWithID(fs, args)
	if err != nil {
		return fmt.Errorf("policies %s: %w (usage: hookmon-cli policies %s <id> --fleet | --host HOST_ID)", verb, err, verb)
	}
	hostID, err := scope()
	if err != nil {
		return fmt.Errorf("policies %s: %w", verb, err)
	}
	req := map[string]string{"scope": "fleet"}
	if hostID != "" {
		req = map[string]string{"scope": "host", "host_id": hostID}
	}
	data, _ := json.Marshal(req)
	body, err := c.do(http.MethodPost, "/api/v1/policies/"+url.PathEscape(id)+"/"+verb, data, http.StatusOK)
	if err != nil {
		return err
	}
	return c.prettyPrint(body)
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
