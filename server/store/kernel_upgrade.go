package store

import (
	"context"
	"fmt"

	"github.com/dlenrow/hookmon/pkg/allowlist"
	"github.com/dlenrow/hookmon/pkg/event"
)

// KernelUpgrades finds hosts with recent kernel changes and correlates
// their PENDING BPF entries against APPROVED BPF entries by prog_name
// and prog_type.
func (s *Store) KernelUpgrades(ctx context.Context) ([]event.KernelUpgrade, error) {
	// 1. Find hosts that changed kernels (prev_kernel_release is set).
	hosts, err := s.hostsWithKernelChange(ctx)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, nil
	}

	// 2. Get all PENDING BPF entries.
	pending, err := s.QueryAllowlist(ctx, event.StatusPending)
	if err != nil {
		return nil, fmt.Errorf("query pending: %w", err)
	}
	var pendingBPF []*event.AllowlistEntry
	for _, e := range pending {
		if e.Learned != nil && isBPFKey(e.Learned.Key.SubjectKind) {
			pendingBPF = append(pendingBPF, e)
		}
	}
	if len(pendingBPF) == 0 {
		return nil, nil
	}

	// 3. Get all APPROVED BPF entries.
	decided, err := s.GetDecidedAllowlist(ctx)
	if err != nil {
		return nil, fmt.Errorf("query decided: %w", err)
	}
	type approvedProg struct {
		Name     string
		ProgType uint32
	}
	approvedSet := map[approvedProg]bool{}
	for _, e := range decided {
		if e.Status != event.StatusApproved || e.Action != event.ActionAllow {
			continue
		}
		if e.Learned == nil || !isBPFKey(e.Learned.Key.SubjectKind) {
			continue
		}
		name := progNameFromEntry(e)
		if name != "" {
			approvedSet[approvedProg{name, e.Learned.Key.ProgType}] = true
		}
	}

	// 4. For each PENDING BPF entry, resolve its prog_name from the first
	//    sighting event and check if it matches an approved program.
	type pendingInfo struct {
		entry    *event.AllowlistEntry
		progName string
	}
	var resolved []pendingInfo
	for _, e := range pendingBPF {
		name := progNameFromEntry(e)
		if name == "" && e.Learned != nil && e.Learned.FirstEventID != "" {
			evt, err := s.GetEvent(ctx, e.Learned.FirstEventID)
			if err == nil && evt.BPFDetail != nil {
				name = evt.BPFDetail.ProgName
			}
		}
		resolved = append(resolved, pendingInfo{entry: e, progName: name})
	}

	// 5. Group by kernel transition.
	type transition struct {
		prev, next string
	}
	byTransition := map[transition]*event.KernelUpgrade{}
	hostTransitions := map[string]transition{}

	for _, h := range hosts {
		t := transition{prev: h.PrevKernelRelease, next: h.KernelRelease}
		hostTransitions[h.ID] = t
		u, ok := byTransition[t]
		if !ok {
			u = &event.KernelUpgrade{PrevKernel: t.prev, NewKernel: t.next}
			byTransition[t] = u
		}
		u.Hosts = append(u.Hosts, h.ID)
	}

	for _, p := range resolved {
		if p.entry.Learned == nil {
			continue
		}
		for _, hostID := range p.entry.Learned.Hosts {
			t, ok := hostTransitions[hostID]
			if !ok {
				continue
			}
			u := byTransition[t]
			matched := p.progName != "" && approvedSet[approvedProg{p.progName, p.entry.Learned.Key.ProgType}]
			if matched {
				u.MatchedIDs = appendUnique(u.MatchedIDs, p.entry.ID)
			} else {
				u.UnmatchedIDs = appendUnique(u.UnmatchedIDs, p.entry.ID)
			}
			break
		}
	}

	var out []event.KernelUpgrade
	for _, u := range byTransition {
		if len(u.MatchedIDs) > 0 || len(u.UnmatchedIDs) > 0 {
			out = append(out, *u)
		}
	}
	return out, nil
}

func (s *Store) hostsWithKernelChange(ctx context.Context) ([]*event.Host, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+hostColumns+` FROM hosts WHERE prev_kernel_release != '' AND prev_kernel_release != kernel_release`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*event.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func isBPFKey(kind string) bool {
	return kind == allowlist.SubjectBPFTag || kind == allowlist.SubjectBPFName
}

func progNameFromEntry(e *event.AllowlistEntry) string {
	if e.ProgName != "" {
		return e.ProgName
	}
	if e.Learned != nil && e.Learned.Key.SubjectKind == allowlist.SubjectBPFName {
		return e.Learned.Key.Subject
	}
	return ""
}

func appendUnique(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}
