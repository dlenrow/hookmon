import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import type {
  AllowlistEntry,
  BulkDecision,
  BulkScope,
  DecideResult,
  EventType,
  Host,
  KernelUpgrade,
  LearningWindow,
} from '../api/types';
import { getPolicies, getHosts, getLearning, decidePolicies, getKernelUpgrades } from '../api/client';
import { EVENT_TYPE_CLASS } from '../components/EventCard';
import { formatTimestamp, formatRelativeTime, bpfProgTypeName, truncateHash } from '../utils';

/** Hooks first seen within this gap of each other form one batch, such as one software update. */
const BATCH_GAP_MS = 60 * 60 * 1000;
/** A row's "same time" filter covers this long on each side of its first sighting. */
const SAME_TIME_MS = 10 * 60 * 1000;
/** The confirmation lists this many of the selected hooks by name. */
const CONFIRM_LIST = 10;

export function subjectLabel(entry: AllowlistEntry): string {
  const k = entry.learned?.key;
  if (!k) return '-';
  switch (k.subject_kind) {
    case 'bpf_tag':
      return `BPF tag ${k.subject} (${bpfProgTypeName(k.prog_type ?? 0)})`;
    case 'bpf_name':
      return `BPF program "${k.subject}", no tag (${bpfProgTypeName(k.prog_type ?? 0)})`;
    case 'ld_preload':
      return `LD_PRELOAD ${truncateHash(k.subject || '')}`;
    case 'ld_audit':
      return `LD_AUDIT ${truncateHash(k.subject || '')}`;
    case 'ld_library_path':
      return `LD_LIBRARY_PATH ${k.subject}`;
    case 'ld_debug':
      return 'LD_DEBUG';
    case 'scan_truncated':
      return 'truncated env scan';
    case 'dlopen':
      return `dlopen ${truncateHash(k.subject || '')}`;
    case 'lib_replace':
      return `library ${k.subject}${k.content_hash ? ` (${truncateHash(k.content_hash)})` : ''}`;
    case 'linker_config':
      return `linker config ${k.subject}${k.content_hash ? ` (${truncateHash(k.content_hash)})` : ''}`;
    case 'shm_pattern':
      return `/dev/shm pattern ${k.subject}`;
    case 'shm_name':
      return `/dev/shm/${k.subject}`;
    case 'rpath':
      return `RPATH in ${truncateHash(k.subject || '')}`;
    case 'ptrace':
      return `ptrace from ${truncateHash(k.subject || '')}`;
    default:
      return k.subject || '-';
  }
}

function eventTypeOf(entry: AllowlistEntry): string {
  return entry.event_types?.[0] || '-';
}

function firstSeenMs(entry: AllowlistEntry): number {
  const t = entry.learned ? Date.parse(entry.learned.first_seen) : NaN;
  return Number.isNaN(t) ? 0 : t;
}

/** A datetime-local value (local time, to the second) for a time in ms. */
function toLocalInput(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** A datetime-local value as ms, or null when empty or invalid. */
function fromLocalInput(v: string): number | null {
  if (!v) return null;
  const t = new Date(v).getTime();
  return Number.isNaN(t) ? null : t;
}

interface Batch {
  rows: AllowlistEntry[];
  /** Earliest and latest first sighting in the batch, in ms. */
  start: number;
  end: number;
  /** Union of all hosts in the batch. */
  hosts: Set<string>;
}

function hostsOf(e: AllowlistEntry): Set<string> {
  return new Set(e.learned?.hosts || []);
}

function hostsOverlap(a: Set<string>, b: Set<string>): boolean {
  if (a.size === 0 || b.size === 0) return true;
  for (const h of a) if (b.has(h)) return true;
  return false;
}

/**
 * Splits rows sorted newest first into batches whose first sightings are
 * close together AND whose host sets overlap, so entries from the same
 * software update cluster together but unrelated events on disjoint hosts
 * do not.
 */
function batches(rows: AllowlistEntry[]): Batch[] {
  const out: Batch[] = [];
  for (const row of rows) {
    const t = firstSeenMs(row);
    const rHosts = hostsOf(row);
    let placed = false;
    for (let i = out.length - 1; i >= 0; i--) {
      const b = out[i];
      if (t > b.end + BATCH_GAP_MS) break;
      if (b.start - t <= BATCH_GAP_MS && hostsOverlap(rHosts, b.hosts)) {
        b.rows.push(row);
        b.start = Math.min(b.start, t);
        b.end = Math.max(b.end, t);
        for (const h of rHosts) b.hosts.add(h);
        placed = true;
        break;
      }
    }
    if (!placed) {
      out.push({ rows: [row], start: t, end: t, hosts: rHosts });
    }
  }
  return out;
}

interface PendingDecision {
  decision: BulkDecision;
  scope: BulkScope;
  entries: AllowlistEntry[];
}

interface DecisionSummary {
  decision: BulkDecision;
  scope: BulkScope;
  total: number;
  ok: number;
  failed: { id: string; label: string; error: string }[];
}

function scopeSentence(decision: BulkDecision, scope: BulkScope, hostCount: number): string {
  const where =
    scope === 'fleet'
      ? 'on every host in the fleet'
      : `only on the host${hostCount === 1 ? '' : 's'} where each was seen (${hostCount} host${hostCount === 1 ? '' : 's'}). On any other host it is a new hook again`;
  return decision === 'approve'
    ? `They will never alert again, ${where}.`
    : `Each will alert every time it happens again, ${where}.`;
}

interface NewHooksProps {
  /** Called after a decision, so the navigation count follows. */
  onChanged?: () => void;
  /** Live first sightings the app has received so far; it only grows. */
  arrivals?: number;
}

/**
 * New hooks: every kind of hook HookMon has not seen before (a PENDING
 * entry), one row per kind however often it has happened since. The
 * operator investigates each, then allows it (benign, never alerts again)
 * or denies it (alerts every time it happens again), one at a time or as a
 * batch, such as everything a software update brought.
 *
 * The list does not change under the operator: rows that arrive later are
 * announced and loaded on Refresh, and a decision applies only to the rows
 * selected and shown when it was confirmed.
 */
export function NewHooks({ onChanged, arrivals = 0 }: NewHooksProps) {
  const [pending, setPending] = useState<AllowlistEntry[]>([]);
  const [hosts, setHosts] = useState<Record<string, Host>>({});
  const [windows, setWindows] = useState<LearningWindow[]>([]);
  const [kernelUpgrades, setKernelUpgrades] = useState<KernelUpgrade[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [arrivalsAtLoad, setArrivalsAtLoad] = useState(arrivals);

  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [hostFilter, setHostFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [text, setText] = useState('');

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [scope, setScope] = useState<BulkScope>('fleet');
  const [confirm, setConfirm] = useState<PendingDecision | null>(null);
  const [busy, setBusy] = useState(false);
  const [summary, setSummary] = useState<DecisionSummary | null>(null);

  const [searchParams] = useSearchParams();
  const focus = searchParams.get('focus') || '';
  const focusRef = useRef<HTMLTableRowElement | null>(null);

  const arrivalsRef = useRef(arrivals);
  arrivalsRef.current = arrivals;

  const load = useCallback(async () => {
    setError(null);
    const seen = arrivalsRef.current;
    try {
      const [entries, hostList, learning, upgrades] = await Promise.all([
        getPolicies('PENDING'),
        getHosts(),
        getLearning(),
        getKernelUpgrades().catch(() => [] as KernelUpgrade[]),
      ]);
      setPending(entries || []);
      const byID: Record<string, Host> = {};
      for (const h of hostList || []) byID[h.id] = h;
      setHosts(byID);
      setWindows(learning.windows || []);
      setKernelUpgrades(upgrades || []);
      setArrivalsAtLoad(seen);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load new hooks');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const hostName = useCallback((id: string): string => hosts[id]?.hostname || id, [hosts]);

  const fromMs = fromLocalInput(from);
  // The "to" field is to the second; it includes that whole second.
  const toMsRaw = fromLocalInput(to);
  const toMs = toMsRaw === null ? null : toMsRaw + 999;

  const shown = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return pending
      .filter((entry) => {
        const l = entry.learned;
        const first = firstSeenMs(entry);
        if (fromMs !== null && first < fromMs) return false;
        if (toMs !== null && first > toMs) return false;
        if (hostFilter && !(l?.hosts || []).includes(hostFilter)) return false;
        if (typeFilter && eventTypeOf(entry) !== typeFilter) return false;
        if (needle) {
          const hay = [
            entry.description,
            l?.exe_path,
            l?.key.subject,
            subjectLabel(entry),
            eventTypeOf(entry),
            ...(l?.hosts || []).map(hostName),
          ]
            .join(' ')
            .toLowerCase();
          if (!hay.includes(needle)) return false;
        }
        return true;
      })
      .sort((a, b) => firstSeenMs(b) - firstSeenMs(a));
  }, [pending, fromMs, toMs, hostFilter, typeFilter, text, hostName]);

  // A selection only ever holds rows that are shown: a filter change drops
  // the rest, so a decision never reaches a row the operator cannot see.
  useEffect(() => {
    const ids = new Set(shown.map((e) => e.id));
    setSelected((prev) => {
      let changed = false;
      const next = new Set<string>();
      for (const id of prev) {
        if (ids.has(id)) next.add(id);
        else changed = true;
      }
      return changed ? next : prev;
    });
  }, [shown]);

  useEffect(() => {
    if (focus && focusRef.current) focusRef.current.scrollIntoView({ block: 'center' });
  }, [focus, shown]);

  const groups = useMemo(() => batches(shown), [shown]);
  const selectedEntries = shown.filter((e) => selected.has(e.id));
  const allShownSelected = shown.length > 0 && selectedEntries.length === shown.length;

  const hostOptions = useMemo(() => {
    const ids = new Set<string>();
    for (const e of pending) for (const h of e.learned?.hosts || []) ids.add(h);
    return [...ids].sort((a, b) => hostName(a).localeCompare(hostName(b)));
  }, [pending, hostName]);

  const typeOptions = useMemo(() => [...new Set(pending.map(eventTypeOf))].sort(), [pending]);

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function setMany(ids: string[], on: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const id of ids) {
        if (on) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  }

  function sameTime(entry: AllowlistEntry) {
    const t = firstSeenMs(entry);
    setFrom(toLocalInput(t - SAME_TIME_MS));
    setTo(toLocalInput(t + SAME_TIME_MS));
  }

  function clearFilters() {
    setFrom('');
    setTo('');
    setHostFilter('');
    setTypeFilter('');
    setText('');
  }

  function ask(decision: BulkDecision) {
    if (selectedEntries.length === 0) return;
    setSummary(null);
    setConfirm({ decision, scope, entries: selectedEntries });
  }

  async function submit() {
    if (!confirm) return;
    const { decision, scope: chosen, entries } = confirm;
    const ids = entries.map((e) => e.id);
    setBusy(true);
    setError(null);
    try {
      const res = await decidePolicies(ids, decision, chosen);
      const byID = new Map<string, DecideResult>();
      for (const r of res.results || []) byID.set(r.id, r);
      const okIDs = new Set<string>();
      const failed: DecisionSummary['failed'] = [];
      for (const e of entries) {
        const r = byID.get(e.id);
        if (r?.ok) okIDs.add(e.id);
        else failed.push({ id: e.id, label: subjectLabel(e), error: r ? r.error || 'failed' : 'no result returned' });
      }
      setPending((prev) => prev.filter((e) => !okIDs.has(e.id)));
      // Failed rows stay selected, ready to retry or to look at.
      setSelected(new Set(failed.map((f) => f.id)));
      setSummary({ decision, scope: chosen, total: ids.length, ok: okIDs.size, failed });
      setConfirm(null);
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${decision === 'approve' ? 'allow' : 'deny'} the new hooks`);
      setConfirm(null);
    } finally {
      setBusy(false);
    }
  }

  const active = windows.filter((w) => w.active);
  const newArrivals = Math.max(0, arrivals - arrivalsAtLoad);
  const filtered = !!(from || to || hostFilter || typeFilter || text);

  const confirmHosts = confirm ? new Set(confirm.entries.flatMap((e) => e.learned?.hosts || [])).size : 0;
  const n = confirm?.entries.length ?? 0;
  const hooksWord = (k: number) => `${k} new hook${k === 1 ? '' : 's'}`;

  return (
    <>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h2>New hooks</h2>
            <p>
              Hooks HookMon had not seen before: one row per kind of hook (event type, program and subject such as
              the BPF tag or library), however often it has happened since. Investigate each, then allow it
              (benign: it never alerts again) or deny it (it alerts every time it happens again). After a software
              update, filter to the update's time, select all shown and decide them together.
            </p>
          </div>
          <button className="btn btn-ghost" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      <div className="page-body">
        <div className="card" style={{ marginBottom: '16px' }}>
          <div className="card-body" style={{ fontSize: '13px' }} data-testid="quiet-status">
            {active.length === 0 ? (
              <span style={{ color: 'var(--text-muted)' }}>
                No quiet period. A new hook's first sighting goes to the alert connectors by its severity. For a
                first deployment or a planned rollout, start a quiet period with{' '}
                <span className="mono">hookmon-cli learning start --fleet --for 7d</span> (or{' '}
                <span className="mono">--host &lt;host-id&gt;</span>): new hooks are still listed here, but not
                sent to alert connectors.
              </span>
            ) : (
              active.map((w) => (
                <div key={w.scope + (w.host_id || '')}>
                  Quiet period on for {w.scope === 'fleet' ? 'the fleet' : hostName(w.host_id || '')} until{' '}
                  {formatTimestamp(w.ends_at)}: new hooks are listed here but not sent to alert connectors.
                </div>
              ))
            )}
          </div>
        </div>

        {kernelUpgrades.length > 0 && (
          <div style={{ marginBottom: '16px' }}>
            {kernelUpgrades.map((ku) => {
              const total = (ku.matched_ids?.length || 0) + (ku.unmatched_ids?.length || 0);
              const matched = ku.matched_ids?.length || 0;
              const unmatched = ku.unmatched_ids?.length || 0;
              return (
                <div key={`${ku.prev_kernel}-${ku.new_kernel}`} className="card" style={{ marginBottom: '8px' }} data-testid="kernel-upgrade">
                  <div className="card-body" style={{ fontSize: '13px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div>
                        <strong>Kernel {ku.prev_kernel} → {ku.new_kernel}</strong> on{' '}
                        {ku.hosts?.length || 0} host{(ku.hosts?.length || 0) === 1 ? '' : 's'}.{' '}
                        {total} program{total === 1 ? ' has a' : 's have'} new tag{total === 1 ? '' : 's'}.{' '}
                        {matched > 0 && (
                          <span style={{ color: 'var(--success)' }}>
                            {matched} match{matched === 1 ? 'es' : ''} program{matched === 1 ? '' : 's'} allowed under the previous kernel.{' '}
                          </span>
                        )}
                        {unmatched > 0 && (
                          <span style={{ color: 'var(--severity-alert)' }}>
                            {unmatched} {unmatched === 1 ? 'does' : 'do'} not match: review.
                          </span>
                        )}
                      </div>
                      {matched > 0 && (
                        <button
                          className="btn btn-primary btn-sm"
                          disabled={busy}
                          onClick={() => {
                            const entries = pending.filter((e) => ku.matched_ids?.includes(e.id));
                            if (entries.length > 0) {
                              setSummary(null);
                              setConfirm({ decision: 'approve', scope: 'fleet', entries });
                            }
                          }}
                        >
                          Allow {matched} matched
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {newArrivals > 0 && (
          <div className="card notice-card" data-testid="new-arrivals">
            <div className="card-body">
              <span>
                {hooksWord(newArrivals)} arrived since this list loaded. They are not in the list or the selection.
              </span>
              <button className="btn btn-ghost btn-sm" onClick={load}>
                Refresh
              </button>
            </div>
          </div>
        )}

        {error && <div className="error-banner">{error}</div>}

        {summary && (
          <div className="card" style={{ marginBottom: '16px' }} data-testid="decide-summary">
            <div className="card-body" style={{ fontSize: '13px' }}>
              <div style={{ color: summary.failed.length ? 'var(--severity-alert)' : 'var(--success)' }}>
                {summary.decision === 'approve' ? 'Allowed' : 'Denied'} {summary.ok} of {hooksWord(summary.total)}{' '}
                {summary.scope === 'fleet' ? 'for the whole fleet' : 'on the hosts where each was seen'}.
                {summary.failed.length > 0 && ` ${summary.failed.length} failed and ${summary.failed.length === 1 ? 'is' : 'are'} still listed and selected:`}
              </div>
              {summary.failed.length > 0 && (
                <ul style={{ margin: '8px 0 0 18px' }}>
                  {summary.failed.map((f) => (
                    <li key={f.id} data-testid="decide-failure" data-entry-id={f.id}>
                      <span className="mono">{f.label}</span> ({f.id}): {f.error}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}

        {loading ? (
          <div className="loading">Loading new hooks</div>
        ) : pending.length === 0 ? (
          <div className="empty-state" data-testid="new-hooks-empty">
            <h3>No new hooks</h3>
            <p>Every hook seen so far has been allowed or denied. A hook HookMon has not seen before appears here.</p>
          </div>
        ) : (
          <>
            <div className="filter-bar">
              <label className="filter-field">
                First seen from
                <input
                  type="datetime-local"
                  step={1}
                  className="form-input"
                  value={from}
                  onChange={(e) => setFrom(e.target.value)}
                  data-testid="filter-from"
                />
              </label>
              <label className="filter-field">
                to
                <input
                  type="datetime-local"
                  step={1}
                  className="form-input"
                  value={to}
                  onChange={(e) => setTo(e.target.value)}
                  data-testid="filter-to"
                />
              </label>
              <select
                className="form-select"
                value={hostFilter}
                onChange={(e) => setHostFilter(e.target.value)}
                data-testid="filter-host"
                aria-label="Host"
              >
                <option value="">All hosts</option>
                {hostOptions.map((h) => (
                  <option key={h} value={h}>
                    {hostName(h)}
                  </option>
                ))}
              </select>
              <select
                className="form-select"
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                data-testid="filter-type"
                aria-label="Event type"
              >
                <option value="">All event types</option>
                {typeOptions.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <input
                type="text"
                className="form-input"
                placeholder="Program, library, tag, host..."
                value={text}
                onChange={(e) => setText(e.target.value)}
                style={{ width: '220px' }}
                data-testid="filter-text"
                aria-label="Search"
              />
              {filtered && (
                <button className="btn btn-ghost btn-sm" onClick={clearFilters}>
                  Clear filters
                </button>
              )}
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }} data-testid="shown-count">
                {shown.length} of {pending.length} shown
              </span>
            </div>

            <div className="bulk-bar" data-testid="bulk-bar">
              <span data-testid="selected-count">{selectedEntries.length} selected</span>
              <select
                className="form-select"
                value={scope}
                onChange={(e) => setScope(e.target.value as BulkScope)}
                data-testid="bulk-scope"
                aria-label="Decide for"
              >
                <option value="fleet">for the whole fleet</option>
                <option value="seen_hosts">only on the hosts where each was seen</option>
              </select>
              <button
                className="btn btn-primary"
                disabled={selectedEntries.length === 0 || busy}
                onClick={() => ask('approve')}
              >
                Allow — ignore in future
              </button>
              <button
                className="btn btn-danger"
                disabled={selectedEntries.length === 0 || busy}
                onClick={() => ask('reject')}
              >
                Deny — alert every time
              </button>
              {selectedEntries.length > 0 && (
                <button className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set())}>
                  Clear selection
                </button>
              )}
            </div>

            {shown.length === 0 ? (
              <div className="empty-state">
                <h3>No new hooks match the filters</h3>
                <p>{pending.length} new hooks are hidden by the filters.</p>
              </div>
            ) : (
              <div className="card">
                <div style={{ overflowX: 'auto' }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th style={{ width: '32px' }}>
                          <input
                            type="checkbox"
                            aria-label="Select all shown"
                            data-testid="select-all-shown"
                            checked={allShownSelected}
                            ref={(el) => {
                              if (el) el.indeterminate = selectedEntries.length > 0 && !allShownSelected;
                            }}
                            onChange={() => setMany(shown.map((e) => e.id), !allShownSelected)}
                          />
                        </th>
                        <th>First seen</th>
                        <th>Type</th>
                        <th>What</th>
                        <th>Program</th>
                        <th>Hosts</th>
                        <th>Seen</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {groups.map((g) => {
                        const ids = g.rows.map((r) => r.id);
                        const allIn = ids.every((id) => selected.has(id));
                        return [
                          g.rows.length > 1 && (
                            <tr key={`batch-${ids[0]}`} className="batch-row" data-testid="batch-row">
                              <td>
                                <input
                                  type="checkbox"
                                  aria-label={`Select the ${g.rows.length} hooks of this batch`}
                                  data-testid="select-batch"
                                  checked={allIn}
                                  onChange={() => setMany(ids, !allIn)}
                                />
                              </td>
                              <td colSpan={7}>
                                {g.rows.length} new hooks first seen {formatTimestamp(new Date(g.start).toISOString())}
                                {g.end !== g.start && ` to ${formatTimestamp(new Date(g.end).toISOString())}`}, on{' '}
                                {g.hosts.size} host{g.hosts.size === 1 ? '' : 's'}
                              </td>
                            </tr>
                          ),
                          ...g.rows.map((entry) => {
                            const l = entry.learned;
                            const type = eventTypeOf(entry);
                            const rowHosts = l?.hosts || [];
                            const isFocus = entry.id === focus;
                            const isSel = selected.has(entry.id);
                            return (
                              <tr
                                key={entry.id}
                                ref={isFocus ? focusRef : undefined}
                                className={`${isSel ? 'row-selected' : ''} ${isFocus ? 'row-focus' : ''}`}
                                data-testid="hook-row"
                                data-entry-id={entry.id}
                              >
                                <td>
                                  <input
                                    type="checkbox"
                                    aria-label={`Select ${subjectLabel(entry)}`}
                                    data-testid="hook-select"
                                    checked={isSel}
                                    onChange={() => toggle(entry.id)}
                                  />
                                </td>
                                <td style={{ whiteSpace: 'nowrap', fontSize: '12px' }}>
                                  <button
                                    type="button"
                                    className="link-button mono"
                                    title="Show the hooks first seen within 10 minutes of this one"
                                    data-testid="same-time"
                                    onClick={() => sameTime(entry)}
                                  >
                                    {l ? formatTimestamp(l.first_seen) : '-'}
                                  </button>
                                  <div style={{ color: 'var(--text-muted)' }}>{l ? formatRelativeTime(l.first_seen) : ''}</div>
                                </td>
                                <td>
                                  <span className={`badge ${EVENT_TYPE_CLASS[type as EventType] || 'badge-type'}`}>{type}</span>
                                </td>
                                <td style={{ maxWidth: '320px', overflowWrap: 'anywhere' }} title={entry.description}>
                                  <span className="mono" style={{ fontSize: '12px' }}>
                                    {subjectLabel(entry)}
                                  </span>
                                </td>
                                <td style={{ maxWidth: '280px', overflowWrap: 'anywhere' }}>
                                  <div className="mono" style={{ fontSize: '12px' }}>{l?.exe_path || '-'}</div>
                                </td>
                                <td style={{ fontSize: '12px' }}>
                                  {rowHosts.slice(0, 3).map((h) => (
                                    <div key={h} className="mono">
                                      {hostName(h)}
                                    </div>
                                  ))}
                                  {rowHosts.length > 3 && (
                                    <div style={{ color: 'var(--text-muted)' }} title={rowHosts.map(hostName).join(', ')}>
                                      and {rowHosts.length - 3} more
                                    </div>
                                  )}
                                </td>
                                <td style={{ fontSize: '12px', whiteSpace: 'nowrap' }}>
                                  <div>{l?.occurrences ?? 0} times</div>
                                  <div style={{ color: 'var(--text-muted)' }}>last {l ? formatRelativeTime(l.last_seen) : '-'}</div>
                                </td>
                                <td style={{ whiteSpace: 'nowrap' }}>
                                  {l?.first_event_id ? (
                                    <Link to={`/events/${l.first_event_id}`} className="btn btn-ghost btn-sm" data-testid="hook-evidence">
                                      Evidence
                                    </Link>
                                  ) : (
                                    <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>no event</span>
                                  )}
                                </td>
                              </tr>
                            );
                          }),
                        ];
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {confirm && (
        <div className="modal-overlay" onClick={() => !busy && setConfirm(null)}>
          <div className="modal" style={{ maxWidth: '640px' }} onClick={(e) => e.stopPropagation()} data-testid="confirm-dialog">
            <div className="modal-header">
              <h3>
                {confirm.decision === 'approve' ? 'Allow' : 'Deny'} {hooksWord(n)}{' '}
                {confirm.scope === 'fleet' ? 'for the whole fleet' : 'on the hosts where each was seen'}?
              </h3>
            </div>
            <div className="modal-body">
              <p style={{ fontSize: '13px', marginBottom: '12px' }} data-testid="confirm-scope">
                {scopeSentence(confirm.decision, confirm.scope, confirmHosts)}
              </p>
              <ul style={{ fontSize: '12px', margin: '0 0 12px 18px' }}>
                {confirm.entries.slice(0, CONFIRM_LIST).map((e) => (
                  <li key={e.id} className="mono">
                    {eventTypeOf(e)} {subjectLabel(e)}
                    {e.learned?.exe_path ? ` by ${e.learned.exe_path}` : ''}
                  </li>
                ))}
              </ul>
              {n > CONFIRM_LIST && (
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>and {n - CONFIRM_LIST} more</p>
              )}
              <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                {confirm.decision === 'approve'
                  ? 'To undo, delete or disable the entries on the Policies page.'
                  : 'To undo, delete the entries on the Policies page; the hook is then new again.'}
              </p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-ghost" disabled={busy} onClick={() => setConfirm(null)}>
                Cancel
              </button>
              <button
                className={`btn ${confirm.decision === 'approve' ? 'btn-primary' : 'btn-danger'}`}
                disabled={busy}
                onClick={submit}
                data-testid="confirm-decision"
              >
                {busy ? 'Saving' : `${confirm.decision === 'approve' ? 'Allow' : 'Deny'} ${hooksWord(n)}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
