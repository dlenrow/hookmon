package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/dlenrow/hookmon/pkg/version"
)

func main() {
	serverURL := flag.String("server", "http://localhost:8443", "hookmon-server URL")
	token := flag.String("token", "", "API authentication token")
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

	cli := &CLI{
		baseURL: strings.TrimRight(*serverURL, "/"),
		token:   *token,
		client:  &http.Client{},
	}

	var err error
	switch args[0] {
	case "events":
		err = cli.listEvents(args[1:])
	case "hosts":
		err = cli.listHosts()
	case "policies":
		if len(args) > 1 && args[1] == "create" {
			err = cli.createPolicy(args[2:])
		} else if len(args) > 1 && args[1] == "delete" {
			if len(args) < 3 {
				err = fmt.Errorf("usage: hookmon-cli policies delete <id>")
			} else {
				err = cli.deletePolicy(args[2])
			}
		} else {
			err = cli.listPolicies()
		}
	case "health":
		err = cli.health()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: hookmon-cli [flags] <command> [args]

Commands:
  events              List recent events
  events --limit N    List N most recent events
  hosts               List monitored hosts
  policies            List allowlist policies
  policies create     Create a policy (reads JSON from stdin)
  policies delete ID  Delete a policy
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
}

func (c *CLI) listEvents(args []string) error {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	limit := fs.Int("limit", 50, "max events to return")
	hostID := fs.String("host", "", "filter by host ID")
	eventType := fs.String("type", "", "filter by event type")
	fs.Parse(args)

	url := fmt.Sprintf("%s/api/v1/events?limit=%d", c.baseURL, *limit)
	if *hostID != "" {
		url += "&host_id=" + *hostID
	}
	if *eventType != "" {
		url += "&event_type=" + *eventType
	}

	return c.getAndPrint(url)
}

func (c *CLI) listHosts() error {
	return c.getAndPrint(c.baseURL + "/api/v1/hosts")
}

func (c *CLI) listPolicies() error {
	return c.getAndPrint(c.baseURL + "/api/v1/policies")
}

func (c *CLI) createPolicy(args []string) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/v1/policies", strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
	}
	return prettyPrint(body)
}

func (c *CLI) deletePolicy(id string) error {
	req, err := http.NewRequest("DELETE", c.baseURL+"/api/v1/policies/"+id, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		fmt.Println("Policy deleted.")
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
}

func (c *CLI) health() error {
	return c.getAndPrint(c.baseURL + "/api/v1/health")
}

func (c *CLI) getAndPrint(url string) error {
	req, err := http.NewRequest("GET", url, nil)
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
	return prettyPrint(body)
}

func prettyPrint(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Println(string(data))
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
