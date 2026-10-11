import { useState, useEffect, useCallback } from 'react';
import type { AllowlistEntry, Host, LearningWindow, Scope } from '../api/types';
import { getPolicies, getHosts, getLearning, decidePolicy } from '../api/client';
import { formatTimestamp, formatRelativeTime, bpfProgTypeName, truncateHash } from '../utils';

/** A row's chosen scope: "fleet" or a host ID. */
type ScopeChoice = string;

function subjectLabel(entry: AllowlistEntry): string {
  const k = entry.learned?.key;
  if (!k) return '-';
  switch (k.subject_kind) {
    case 'bpf_tag':
      return `BPF tag ${k.subject} (${bpfProgTypeName(k.prog_type ?? 0)})`;
    case 'bpf_name':
      return `BPF program "${k.subject}", no tag (${bpfProgTypeName(k.prog_type ?? 0)})`;
    case 'library_hash':
      return `library ${truncateHash(k.subject || '')}`;
    case 'library_path':
      return `library ${k.subject}`;
    case 'shm_pattern':
      return `/dev/shm pattern ${k.subject}`;
    case 'shm_name':
      return `/dev/shm/${k.subject}`;
    case 'file_path':
      return k.subject || '-';
    default:
      return 'the binary itself';
  }
}

export function PendingApproval() {
  const [pending, setPending] = useState<AllowlistEntry[]>([]);
  const [hosts, setHosts] = useState<Record<string, Host>>({});
  const [windows, setWindows] = useState<LearningWindow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [scopes, setScopes] = useState<Record<string, ScopeChoice>>({});
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [entries, hostList, learning] = await Promise.all([
        getPolicies('PENDING'),
        getHosts(),
        getLearning(),
      ]);
      setPending(entries || []);
      const byID: Record<string, Host> = {};
      for (const h of hostList || []) byID[h.id] = h;
      setHosts(byID);
      setWindows(learning.windows || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load PENDING entries');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  function hostName(id: string): string {
    return hosts[id]?.hostname || id;
  }

  async function decide(entry: AllowlistEntry, decision: 'approve' | 'reject') {
    const choice = scopes[entry.id] || 'fleet';
    const scope: Scope = choice === 'fleet' ? { scope: 'fleet' } : { scope: 'host', host_id: choice };
    setBusy(entry.id);
    setError(null);
    try {
      await decidePolicy(entry.id, decision, scope);
      setNotice(
        `${decision === 'approve' ? 'Approved (ALLOW)' : 'Rejected (keeps alerting)'} for ${
          choice === 'fleet' ? 'the fleet' : hostName(choice)
        }: ${entry.description}`
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${decision}`);
    } finally {
      setBusy(null);
    }
  }

  const active = windows.filter((w) => w.active);

  return (
    <>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h2>Pending Approval</h2>
            <p>
              Learning-mode candidates: one per unique event type, binary and subject seen while no allowlist
              entry matched. Approve to allow, reject to keep alerting, for the fleet or one host.
            </p>
          </div>
          <button className="btn btn-ghost" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      <div className="page-body">
        <div className="card" style={{ marginBottom: '16px' }}>
          <div className="card-body" style={{ fontSize: '13px' }} data-testid="learning-status">
            {active.length === 0 ? (
              <span style={{ color: 'var(--text-muted)' }}>
                Learning mode is off. Start it with{' '}
                <span className="mono">hookmon-cli learning start --fleet --for 7d</span> (or{' '}
                <span className="mono">--host &lt;host-id&gt;</span>).
              </span>
            ) : (
              active.map((w) => (
                <div key={w.scope + (w.host_id || '')}>
                  Learning mode is on for {w.scope === 'fleet' ? 'the fleet' : hostName(w.host_id || '')} until{' '}
                  {formatTimestamp(w.ends_at)}.
                </div>
              ))
            )}
          </div>
        </div>

        {error && <div className="error-banner">{error}</div>}
        {notice && (
          <div className="card" style={{ marginBottom: '16px' }}>
            <div className="card-body" style={{ fontSize: '13px', color: 'var(--success)' }} data-testid="pending-notice">
              {notice}
            </div>
          </div>
        )}

        {loading ? (
          <div className="loading">Loading PENDING entries</div>
        ) : pending.length === 0 ? (
          <div className="empty-state">
            <h3>Nothing to review</h3>
            <p>Learning mode records a PENDING entry for each new unmatched event.</p>
          </div>
        ) : (
          <div className="card">
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Event Type</th>
                    <th>Binary</th>
                    <th>Subject</th>
                    <th>Seen</th>
                    <th>Hosts</th>
                    <th>Decide for</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {pending.map((entry) => {
                    const l = entry.learned;
                    const k = l?.key;
                    return (
                      <tr key={entry.id} data-testid="pending-row" data-entry-id={entry.id}>
                        <td>
                          <span className="badge badge-type">{k?.event_type || entry.event_types?.[0] || '-'}</span>
                          {k?.in_container && (
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>in a container</div>
                          )}
                        </td>
                        <td>
                          <div className="mono" style={{ fontSize: '12px' }}>{l?.exe_path || '-'}</div>
                          <div className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }} title={k?.exe_hash}>
                            {k?.exe_hash ? truncateHash(k.exe_hash) : 'no exe hash'}
                          </div>
                        </td>
                        <td style={{ maxWidth: '360px', overflowWrap: 'anywhere' }}>
                          <span className="mono" style={{ fontSize: '12px' }}>{subjectLabel(entry)}</span>
                        </td>
                        <td style={{ fontSize: '12px', whiteSpace: 'nowrap' }}>
                          <div>{l?.occurrences ?? 0} times</div>
                          <div style={{ color: 'var(--text-muted)' }}>
                            {l ? `${formatRelativeTime(l.first_seen)} to ${formatRelativeTime(l.last_seen)}` : ''}
                          </div>
                        </td>
                        <td style={{ fontSize: '12px' }}>
                          {(l?.hosts || []).map((h) => (
                            <div key={h} className="mono">{hostName(h)}</div>
                          ))}
                        </td>
                        <td>
                          <select
                            className="form-select"
                            value={scopes[entry.id] || 'fleet'}
                            onChange={(e) => setScopes((s) => ({ ...s, [entry.id]: e.target.value }))}
                          >
                            <option value="fleet">Fleet</option>
                            {(l?.hosts || []).map((h) => (
                              <option key={h} value={h}>
                                Host {hostName(h)}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <button
                            className="btn btn-primary btn-sm"
                            disabled={busy === entry.id}
                            onClick={() => decide(entry, 'approve')}
                            style={{ marginRight: '6px' }}
                          >
                            Approve
                          </button>
                          <button
                            className="btn btn-danger btn-sm"
                            disabled={busy === entry.id}
                            onClick={() => decide(entry, 'reject')}
                          >
                            Reject
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
