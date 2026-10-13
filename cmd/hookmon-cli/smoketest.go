package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

var smoketestTypes = []string{
	"BPF_LOAD",
	"EXEC_INJECTION",
	"SHM_CREATE",
	"DLOPEN",
	"PTRACE_INJECT",
	"LINKER_CONFIG",
	"LIB_INTEGRITY",
	"ELF_RPATH",
}

const smoketestMarker = "hookmon-smoketest"

type smoketestEntry struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`
	Action     string   `json:"action"`
	Enabled    bool     `json:"enabled"`
	EventTypes []string `json:"event_types"`
	Learned    *struct {
		FirstSeen time.Time `json:"first_seen"`
		Hosts     []string  `json:"hosts"`
		ExePath   string    `json:"exe_path"`
	} `json:"learned"`
	ExePath string `json:"exe_path"`
}

func (e *smoketestEntry) isSmoketest() bool {
	if e.Learned != nil && strings.Contains(e.Learned.ExePath, smoketestMarker) {
		return true
	}
	return strings.Contains(e.ExePath, smoketestMarker)
}

// smoketestTypes returns the smoketest grid event types this entry covers.
// BPF entries cover BPF_LOAD/BPF_ATTACH/BPF_INVENTORY but the grid only
// shows BPF_LOAD, so we map to the first match in the smoketest list.
func (e *smoketestEntry) smoketestTypes() []string {
	var types []string
	for _, st := range smoketestTypes {
		for _, et := range e.EventTypes {
			if et == st {
				types = append(types, st)
				break
			}
		}
	}
	return types
}

func (c *CLI) smoketestCheck(args []string) error {
	fs := flag.NewFlagSet("smoketest check", flag.ContinueOnError)
	since := fs.String("since", "", "first seen at or after this time (RFC 3339) or within this duration (90m, 36h, 7d)")
	var hosts flagSlice
	fs.Var(&hosts, "host", "host ID or hostname (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *since == "" {
		return fmt.Errorf("smoketest check: --since is required")
	}
	from, err := parseSince(*since, time.Now())
	if err != nil {
		return fmt.Errorf("smoketest check: --since: %w", err)
	}

	hostIDs, err := c.resolveHosts(hosts)
	if err != nil {
		return err
	}

	body, err := c.do(http.MethodGet, "/api/v1/policies?status=PENDING", nil, http.StatusOK)
	if err != nil {
		return err
	}
	var pending []smoketestEntry
	if err := json.Unmarshal(body, &pending); err != nil {
		return fmt.Errorf("read pending: %w", err)
	}

	body, err = c.do(http.MethodGet, "/api/v1/policies", nil, http.StatusOK)
	if err != nil {
		return err
	}
	var decided []smoketestEntry
	if err := json.Unmarshal(body, &decided); err != nil {
		return fmt.Errorf("read decided: %w", err)
	}

	allHosts := map[string]bool{}
	for _, h := range hostIDs {
		allHosts[h] = true
	}

	type cell struct {
		status string
	}
	grid := map[string]map[string]cell{}

	for _, e := range pending {
		if !e.isSmoketest() || e.Learned == nil {
			continue
		}
		if e.Learned.FirstSeen.Before(from) {
			continue
		}
		for _, h := range e.Learned.Hosts {
			if len(hostIDs) > 0 && !allHosts[h] {
				continue
			}
			allHosts[h] = true
			if grid[h] == nil {
				grid[h] = map[string]cell{}
			}
			for _, et := range e.smoketestTypes() {
				grid[h][et] = cell{status: "new"}
			}
		}
	}

	for _, e := range decided {
		if !e.isSmoketest() || e.Learned == nil {
			continue
		}
		st := "allowed"
		if e.Action == "ALERT" || e.Action == "DENY" || e.Status == "REJECTED" {
			st = "denied"
		}
		for _, h := range e.Learned.Hosts {
			if len(hostIDs) > 0 && !allHosts[h] {
				continue
			}
			allHosts[h] = true
			if grid[h] == nil {
				grid[h] = map[string]cell{}
			}
			for _, et := range e.smoketestTypes() {
				if _, exists := grid[h][et]; !exists {
					grid[h][et] = cell{status: st}
				}
			}
		}
	}

	sortedHosts := make([]string, 0, len(allHosts))
	for h := range allHosts {
		sortedHosts = append(sortedHosts, h)
	}
	sort.Strings(sortedHosts)

	if len(sortedHosts) == 0 {
		fmt.Fprintln(c.out, "no smoketest entries found")
		return fmt.Errorf("smoketest check: no hosts")
	}

	maxType := 0
	for _, t := range smoketestTypes {
		if len(t) > maxType {
			maxType = len(t)
		}
	}

	fmt.Fprintf(c.out, "%-*s", maxType+2, "")
	for _, h := range sortedHosts {
		short := h
		if len(short) > 12 {
			short = short[:12]
		}
		fmt.Fprintf(c.out, " %-12s", short)
	}
	fmt.Fprintln(c.out)

	missing := 0
	for _, t := range smoketestTypes {
		fmt.Fprintf(c.out, "%-*s", maxType+2, t)
		for _, h := range sortedHosts {
			if v, ok := grid[h][t]; !ok {
				fmt.Fprintf(c.out, " %-12s", "MISSING")
				missing++
			} else {
				fmt.Fprintf(c.out, " %-12s", v.status)
			}
		}
		fmt.Fprintln(c.out)
	}

	if missing > 0 {
		return fmt.Errorf("smoketest check: %d cells missing", missing)
	}
	return nil
}

func (c *CLI) smoketestCleanup() error {
	body, err := c.do(http.MethodGet, "/api/v1/policies?status=PENDING", nil, http.StatusOK)
	if err != nil {
		return err
	}
	var pending []smoketestEntry
	json.Unmarshal(body, &pending)

	body, err = c.do(http.MethodGet, "/api/v1/policies", nil, http.StatusOK)
	if err != nil {
		return err
	}
	var decided []smoketestEntry
	json.Unmarshal(body, &decided)

	all := append(pending, decided...)
	deleted := 0
	for _, e := range all {
		if !e.isSmoketest() {
			continue
		}
		if _, err := c.do(http.MethodDelete, "/api/v1/policies/"+e.ID, nil, http.StatusNoContent); err != nil {
			fmt.Fprintf(c.out, "  delete %s: %v\n", e.ID, err)
			continue
		}
		deleted++
	}
	fmt.Fprintf(c.out, "smoketest cleanup: deleted %d entries\n", deleted)
	return nil
}

func (c *CLI) resolveHosts(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	body, err := c.do(http.MethodGet, "/api/v1/hosts", nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var hosts []struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(body, &hosts); err != nil {
		return nil, fmt.Errorf("read hosts: %w", err)
	}
	byName := map[string]string{}
	for _, h := range hosts {
		byName[strings.ToLower(h.Hostname)] = h.ID
		byName[h.ID] = h.ID
	}
	var ids []string
	for _, n := range names {
		id, ok := byName[strings.ToLower(n)]
		if !ok {
			id = n
		}
		ids = append(ids, id)
	}
	return ids, nil
}

type flagSlice []string

func (f *flagSlice) String() string { return strings.Join(*f, ",") }
func (f *flagSlice) Set(v string) error {
	*f = append(*f, v)
	return nil
}
