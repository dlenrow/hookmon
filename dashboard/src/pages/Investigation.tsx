import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import type { HookEvent } from '../api/types';
import { getEvent, getEvents } from '../api/client';
import { SeverityBadge } from '../components/SeverityBadge';
import { TimelineView } from '../components/TimelineView';
import { formatTimestampFull, bpfProgTypeName, bpfCmdName, truncateHash } from '../utils';

export function Investigation() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [event, setEvent] = useState<HookEvent | null>(null);
  const [relatedEvents, setRelatedEvents] = useState<HookEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showRawJson, setShowRawJson] = useState(false);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const evt = await getEvent(id!);
        if (cancelled) return;
        setEvent(evt);

        // Fetch related events from the same host
        if (evt.host_id) {
          try {
            const related = await getEvents({
              host_id: evt.host_id,
              limit: 20,
            });
            if (!cancelled) {
              setRelatedEvents(related);
            }
          } catch {
            // Non-critical: timeline just won't populate
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load event');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    load();
    return () => { cancelled = true; };
  }, [id]);

  if (loading) {
    return (
      <>
        <div className="page-header">
          <h2>Investigation</h2>
        </div>
        <div className="page-body">
          <div className="loading">Loading event details</div>
        </div>
      </>
    );
  }

  if (error || !event) {
    return (
      <>
        <div className="page-header">
          <h2>Investigation</h2>
        </div>
        <div className="page-body">
          <div className="error-banner">{error || 'Event not found'}</div>
          <button className="btn btn-ghost" onClick={() => navigate('/events')}>
            Back to Events
          </button>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button className="btn btn-ghost btn-sm" onClick={() => navigate('/events')}>
            Back
          </button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <h2>Event Investigation</h2>
              <SeverityBadge severity={event.severity} />
              <span className="badge badge-type">{event.event_type}</span>
            </div>
            <p className="mono" style={{ marginTop: '4px' }}>
              ID: {event.id}
            </p>
          </div>
        </div>
      </div>

      <div className="page-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: '24px' }}>
          {/* Main detail panel */}
          <div>
            {/* Event summary */}
            <div className="card" style={{ marginBottom: '24px' }}>
              <div className="card-header">
                <h3>Event Summary</h3>
                <span
                  className="mono"
                  style={{ fontSize: '12px', color: 'var(--text-muted)' }}
                >
                  {formatTimestampFull(event.timestamp)}
                </span>
              </div>
              <div className="card-body">
                <div className="detail-grid">
                  <span className="detail-label">Event Type</span>
                  <span className="detail-value">{event.event_type}</span>

                  <span className="detail-label">Severity</span>
                  <span className="detail-value">
                    <SeverityBadge severity={event.severity} />
                  </span>

                  <span className="detail-label">Host</span>
                  <span className="detail-value mono">
                    {event.hostname} ({event.host_id})
                  </span>

                  <span className="detail-label">Timestamp</span>
                  <span className="detail-value mono">
                    {formatTimestampFull(event.timestamp)}
                  </span>
                </div>
              </div>
            </div>

            {/* Process context */}
            <div className="card" style={{ marginBottom: '24px' }}>
              <div className="card-header">
                <h3>Process Context</h3>
              </div>
              <div className="card-body">
                <div className="detail-grid">
                  <span className="detail-label">PID</span>
                  <span className="detail-value mono">{event.pid}</span>

                  <span className="detail-label">PPID</span>
                  <span className="detail-value mono">{event.ppid}</span>

                  <span className="detail-label">UID / GID</span>
                  <span className="detail-value mono">{event.uid} / {event.gid}</span>

                  <span className="detail-label">Comm</span>
                  <span className="detail-value mono">{event.comm}</span>

                  <span className="detail-label">Cmdline</span>
                  <span className="detail-value mono">{event.cmdline || '-'}</span>

                  <span className="detail-label">Exe Path</span>
                  <span className="detail-value mono">{event.exe_path || '-'}</span>

                  <span className="detail-label">Exe Hash</span>
                  <span className="detail-value mono" title={event.exe_hash}>
                    {event.exe_hash ? truncateHash(event.exe_hash) : '-'}
                  </span>

                  {event.cgroup_path && (
                    <>
                      <span className="detail-label">Cgroup</span>
                      <span className="detail-value mono">{event.cgroup_path}</span>
                    </>
                  )}

                  {event.container_id && (
                    <>
                      <span className="detail-label">Container ID</span>
                      <span className="detail-value mono">{event.container_id}</span>
                    </>
                  )}

                  {event.namespace && (
                    <>
                      <span className="detail-label">Namespace</span>
                      <span className="detail-value mono">{event.namespace}</span>
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* Event-type-specific detail */}
            {event.bpf_detail && (
              <div className="card" style={{ marginBottom: '24px' }}>
                <div className="card-header">
                  <h3>BPF Detail</h3>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <span className="detail-label">BPF Command</span>
                    <span className="detail-value mono">
                      {bpfCmdName(event.bpf_detail.bpf_cmd)} ({event.bpf_detail.bpf_cmd})
                    </span>

                    <span className="detail-label">Program Type</span>
                    <span className="detail-value mono">
                      {bpfProgTypeName(event.bpf_detail.prog_type)} ({event.bpf_detail.prog_type})
                    </span>

                    <span className="detail-label">Program Name</span>
                    <span className="detail-value mono">{event.bpf_detail.prog_name || '-'}</span>

                    <span className="detail-label">Attach Type</span>
                    <span className="detail-value mono">{event.bpf_detail.attach_type}</span>

                    <span className="detail-label">Target FD</span>
                    <span className="detail-value mono">{event.bpf_detail.target_fd}</span>

                    <span className="detail-label">Instruction Count</span>
                    <span className="detail-value mono">{event.bpf_detail.insn_count}</span>

                    {event.bpf_detail.prog_hash && (
                      <>
                        <span className="detail-label">Program Hash</span>
                        <span className="detail-value mono" title={event.bpf_detail.prog_hash}>
                          {truncateHash(event.bpf_detail.prog_hash)}
                        </span>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}

            {event.exec_injection_detail && (
              <div className="card" style={{ marginBottom: '24px' }}>
                <div className="card-header">
                  <h3>Exec Injection Detail</h3>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <span className="detail-label">Library Path</span>
                    <span className="detail-value mono">{event.exec_injection_detail.library_path}</span>

                    <span className="detail-label">Library Hash</span>
                    <span className="detail-value mono" title={event.exec_injection_detail.library_hash}>
                      {event.exec_injection_detail.library_hash ? truncateHash(event.exec_injection_detail.library_hash) : '-'}
                    </span>

                    <span className="detail-label">Target Binary</span>
                    <span className="detail-value mono">{event.exec_injection_detail.target_binary || '-'}</span>

                    <span className="detail-label">Set By</span>
                    <span className="detail-value">{event.exec_injection_detail.set_by || '-'}</span>

                    {event.exec_injection_detail.env_var && (
                      <>
                        <span className="detail-label">Env Variable</span>
                        <span className="detail-value mono">{event.exec_injection_detail.env_var}</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}

            {event.shm_detail && (
              <div className="card" style={{ marginBottom: '24px' }}>
                <div className="card-header">
                  <h3>Shared Memory Detail</h3>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <span className="detail-label">SHM Name</span>
                    <span className="detail-value mono">{event.shm_detail.shm_name}</span>

                    <span className="detail-label">Size</span>
                    <span className="detail-value mono">{event.shm_detail.size} bytes</span>

                    <span className="detail-label">Pattern</span>
                    <span className="detail-value">{event.shm_detail.pattern}</span>
                  </div>
                </div>
              </div>
            )}

            {event.dlopen_detail && (
              <div className="card" style={{ marginBottom: '24px' }}>
                <div className="card-header">
                  <h3>dlopen() Detail</h3>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <span className="detail-label">Library Path</span>
                    <span className="detail-value mono">{event.dlopen_detail.library_path}</span>

                    <span className="detail-label">Library Hash</span>
                    <span className="detail-value mono" title={event.dlopen_detail.library_hash}>
                      {event.dlopen_detail.library_hash ? truncateHash(event.dlopen_detail.library_hash) : '-'}
                    </span>

                    <span className="detail-label">Flags</span>
                    <span className="detail-value mono">{event.dlopen_detail.flags}</span>
                  </div>
                </div>
              </div>
            )}

            {event.linker_config_detail && (
              <div className="card" style={{ marginBottom: '24px' }}>
                <div className="card-header">
                  <h3>Linker Config Detail</h3>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <span className="detail-label">File Path</span>
                    <span className="detail-value mono">{event.linker_config_detail.file_path}</span>

                    <span className="detail-label">Operation</span>
                    <span className="detail-value">{event.linker_config_detail.operation}</span>

                    {event.linker_config_detail.old_hash && (
                      <>
                        <span className="detail-label">Old Hash</span>
                        <span className="detail-value mono" title={event.linker_config_detail.old_hash}>
                          {truncateHash(event.linker_config_detail.old_hash)}
                        </span>
                      </>
                    )}

                    {event.linker_config_detail.new_hash && (
                      <>
                        <span className="detail-label">New Hash</span>
                        <span className="detail-value mono" title={event.linker_config_detail.new_hash}>
                          {truncateHash(event.linker_config_detail.new_hash)}
                        </span>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}

            {event.ptrace_detail && (
              <div className="card" style={{ marginBottom: '24px' }}>
                <div className="card-header">
                  <h3>Ptrace Detail</h3>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <span className="detail-label">Request</span>
                    <span className="detail-value mono">
                      {event.ptrace_detail.request_name} ({event.ptrace_detail.request})
                    </span>

                    <span className="detail-label">Target PID</span>
                    <span className="detail-value mono">{event.ptrace_detail.target_pid}</span>

                    <span className="detail-label">Target Comm</span>
                    <span className="detail-value mono">{event.ptrace_detail.target_comm}</span>

                    {event.ptrace_detail.addr !== undefined && event.ptrace_detail.addr !== 0 && (
                      <>
                        <span className="detail-label">Address</span>
                        <span className="detail-value mono">0x{event.ptrace_detail.addr.toString(16)}</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}

            {event.lib_integrity_detail && (
              <div className="card" style={{ marginBottom: '24px' }}>
                <div className="card-header">
                  <h3>Library Integrity Detail</h3>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <span className="detail-label">Library Path</span>
                    <span className="detail-value mono">{event.lib_integrity_detail.library_path}</span>

                    <span className="detail-label">Operation</span>
                    <span className="detail-value">{event.lib_integrity_detail.operation}</span>

                    {event.lib_integrity_detail.old_hash && (
                      <>
                        <span className="detail-label">Old Hash</span>
                        <span className="detail-value mono" title={event.lib_integrity_detail.old_hash}>
                          {truncateHash(event.lib_integrity_detail.old_hash)}
                        </span>
                      </>
                    )}

                    {event.lib_integrity_detail.new_hash && (
                      <>
                        <span className="detail-label">New Hash</span>
                        <span className="detail-value mono" title={event.lib_integrity_detail.new_hash}>
                          {truncateHash(event.lib_integrity_detail.new_hash)}
                        </span>
                      </>
                    )}

                    <span className="detail-label">In ld.so.cache</span>
                    <span className="detail-value">{event.lib_integrity_detail.in_ld_cache ? 'Yes' : 'No'}</span>
                  </div>
                </div>
              </div>
            )}

            {event.elf_rpath_detail && (
              <div className="card" style={{ marginBottom: '24px' }}>
                <div className="card-header">
                  <h3>ELF RPATH/RUNPATH Detail</h3>
                  <span className={`badge badge-${event.elf_rpath_detail.highest_risk === 'CRITICAL' ? 'critical' : event.elf_rpath_detail.highest_risk === 'HIGH' ? 'alert' : event.elf_rpath_detail.highest_risk === 'MEDIUM' ? 'warn' : 'info'}`}>
                    {event.elf_rpath_detail.highest_risk} RISK
                  </span>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <span className="detail-label">Has RPATH</span>
                    <span className="detail-value">{event.elf_rpath_detail.has_rpath ? 'Yes' : 'No'}</span>

                    <span className="detail-label">Has RUNPATH</span>
                    <span className="detail-value">{event.elf_rpath_detail.has_runpath ? 'Yes' : 'No'}</span>

                    {event.elf_rpath_detail.rpath_raw && (
                      <>
                        <span className="detail-label">RPATH Raw</span>
                        <span className="detail-value mono">{event.elf_rpath_detail.rpath_raw}</span>
                      </>
                    )}

                    {event.elf_rpath_detail.runpath_raw && (
                      <>
                        <span className="detail-label">RUNPATH Raw</span>
                        <span className="detail-value mono">{event.elf_rpath_detail.runpath_raw}</span>
                      </>
                    )}

                    <span className="detail-label">Uses $ORIGIN</span>
                    <span className="detail-value">{event.elf_rpath_detail.uses_origin ? 'Yes' : 'No'}</span>

                    <span className="detail-label">Uses Deprecated DT_RPATH</span>
                    <span className="detail-value">{event.elf_rpath_detail.uses_deprecated ? 'Yes' : 'No'}</span>

                    <span className="detail-label">SUID/SGID Binary</span>
                    <span className="detail-value">{event.elf_rpath_detail.is_setuid ? 'Yes' : 'No'}</span>
                  </div>

                  {event.elf_rpath_detail.entries.length > 0 && (
                    <div style={{ marginTop: '16px' }}>
                      <h4 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px' }}>
                        Path Entries
                      </h4>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Path</th>
                            <th>Risk</th>
                            <th>Type</th>
                            <th>Exists</th>
                            <th>Reason</th>
                          </tr>
                        </thead>
                        <tbody>
                          {event.elf_rpath_detail.entries.map((entry, i) => (
                            <tr key={i}>
                              <td><span className="mono">{entry.path || '(empty)'}</span></td>
                              <td>
                                <span className={`badge badge-${entry.risk === 'CRITICAL' ? 'critical' : entry.risk === 'HIGH' ? 'alert' : entry.risk === 'MEDIUM' ? 'warn' : 'info'}`}>
                                  {entry.risk}
                                </span>
                              </td>
                              <td>{entry.is_rpath ? 'DT_RPATH' : 'DT_RUNPATH'}</td>
                              <td>{entry.exists ? 'Yes' : 'No'}</td>
                              <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{entry.reason}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Policy result */}
            {event.policy_result && (
              <div className="card" style={{ marginBottom: '24px' }}>
                <div className="card-header">
                  <h3>Policy Result</h3>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <span className="detail-label">Action</span>
                    <span className="detail-value">
                      <span className={`badge badge-${event.policy_result.action.toLowerCase()}`}>
                        {event.policy_result.action}
                      </span>
                    </span>

                    {event.policy_result.matched_entry_id && (
                      <>
                        <span className="detail-label">Matched Entry</span>
                        <span className="detail-value mono">{event.policy_result.matched_entry_id}</span>
                      </>
                    )}

                    <span className="detail-label">Reason</span>
                    <span className="detail-value">{event.policy_result.reason}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Raw JSON */}
            <div className="card">
              <div className="card-header">
                <h3>Raw Event JSON</h3>
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => setShowRawJson(!showRawJson)}
                >
                  {showRawJson ? 'Hide' : 'Show'}
                </button>
              </div>
              {showRawJson && (
                <div className="card-body">
                  <pre className="json-display">
                    {JSON.stringify(event, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>

          {/* Right sidebar: timeline */}
          <div>
            <div className="card" style={{ position: 'sticky', top: '24px' }}>
              <div className="card-header">
                <h3>Host Timeline</h3>
              </div>
              <div className="card-body">
                <TimelineView
                  events={relatedEvents}
                  activeEventId={event.id}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
