import { useState, useEffect, useCallback } from 'react';
import type { AllowlistEntry, Host } from '../api/types';
import { getPolicies, getHosts, createPolicy, updatePolicy, patchPolicy, deletePolicy } from '../api/client';
import { AllowlistEditor } from '../components/AllowlistEditor';
import { formatTimestamp, bpfProgTypeName, truncateHash } from '../utils';

/** The criteria an entry sets, one short line each. */
function criteria(p: AllowlistEntry): string[] {
  const out: string[] = [];
  const k = p.learned?.key;
  if (k) {
    const subject = k.subject_kind
      ? `${k.subject_kind.replace('_', ' ')} ${k.subject_kind.endsWith('hash') ? truncateHash(k.subject || '') : k.subject}`
      : 'binary only';
    out.push(`exact key: ${subject}${k.exe_hash ? `, exe ${truncateHash(k.exe_hash)}` : ''}${k.in_container ? ', in a container' : ''}`);
  }
  if (p.exe_path) out.push(`exe ${p.exe_path}`);
  if (p.exe_hash) out.push(`exe ${truncateHash(p.exe_hash)}`);
  if (p.prog_hash) out.push(`BPF tag ${p.prog_hash}`);
  if (p.prog_type !== undefined && p.prog_type !== null) out.push(`prog type ${bpfProgTypeName(p.prog_type)}`);
  if (p.prog_name) out.push(`prog ${p.prog_name}`);
  if (p.library_path) out.push(`library ${p.library_path}`);
  if (p.library_hash) out.push(`library ${truncateHash(p.library_hash)}`);
  if (p.host_pattern) out.push(`hostname ${p.host_pattern}`);
  if (p.container_image) out.push(`container ${p.container_image}`);
  if (p.uid_range) out.push(`uid ${p.uid_range.min}-${p.uid_range.max}`);
  if (p.allowed_rpaths?.length) out.push(`rpaths ${p.allowed_rpaths.join(', ')}`);
  return out;
}

export function PolicyManager() {
  const [policies, setPolicies] = useState<AllowlistEntry[]>([]);
  const [hosts, setHosts] = useState<Record<string, Host>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [editing, setEditing] = useState<AllowlistEntry | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const loadPolicies = useCallback(async () => {
    setError(null);
    try {
      const [data, hostList] = await Promise.all([getPolicies(), getHosts()]);
      setPolicies(data || []);
      const byID: Record<string, Host> = {};
      for (const h of hostList || []) byID[h.id] = h;
      setHosts(byID);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load policies');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  async function handleCreate(entry: Partial<AllowlistEntry>) {
    try {
      setError(null);
      await createPolicy(entry);
      setShowEditor(false);
      await loadPolicies();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create policy');
    }
  }

  async function handleUpdate(entry: Partial<AllowlistEntry>) {
    if (!editing) return;
    try {
      setError(null);
      // PUT replaces every editable field: start from the stored entry, so
      // fields the editor does not show (expiry, UID range) are kept.
      await updatePolicy(editing.id, { ...editing, ...entry });
      setEditing(null);
      await loadPolicies();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update policy');
    }
  }

  async function handleToggle(policy: AllowlistEntry) {
    try {
      setError(null);
      await patchPolicy(policy.id, { enabled: !policy.enabled });
      await loadPolicies();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to change policy');
    }
  }

  async function handleDelete(id: string) {
    try {
      setError(null);
      await deletePolicy(id);
      setDeleteConfirm(null);
      await loadPolicies();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete policy');
    }
  }

  function scopeLabel(p: AllowlistEntry): string {
    if (!p.host_id) return 'Fleet';
    return hosts[p.host_id]?.hostname || p.host_id;
  }

  return (
    <>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h2>Policy Manager</h2>
            <p>Allowlist entries in force (APPROVED and REJECTED). Changes apply to the next event.</p>
          </div>
          <button className="btn btn-primary" onClick={() => setShowEditor(true)}>
            + Create Policy
          </button>
        </div>
      </div>

      <div className="page-body">
        {error && <div className="error-banner">{error}</div>}

        {loading ? (
          <div className="loading">Loading policies</div>
        ) : policies.length === 0 ? (
          <div className="empty-state">
            <h3>No policies configured</h3>
            <p>The allowlist entries in force: allowed and denied hooks. New hooks are decided on the New hooks page.</p>
          </div>
        ) : (
          <div className="card">
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Description</th>
                    <th>Event Types</th>
                    <th>Matches</th>
                    <th>Scope</th>
                    <th>Status</th>
                    <th>Action</th>
                    <th>Enabled</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {policies.map((policy) => (
                    <tr key={policy.id} data-testid="policy-row" data-entry-id={policy.id}>
                      <td>
                        <div style={{ maxWidth: '280px', overflowWrap: 'anywhere' }}>
                          <div style={{ fontWeight: 500 }}>{policy.description || '(no description)'}</div>
                          {policy.created_by && (
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                              by {policy.created_by}
                              {policy.learned ? ` · seen ${policy.learned.occurrences} times` : ''}
                            </div>
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="tag-list">
                          {policy.event_types && policy.event_types.length > 0 ? (
                            policy.event_types.map((et) => (
                              <span key={et} className="badge badge-type">{et}</span>
                            ))
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>All</span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="mono" style={{ fontSize: '11px', maxWidth: '320px', overflowWrap: 'anywhere' }}>
                          {criteria(policy).map((c) => (
                            <div key={c}>{c}</div>
                          ))}
                          {criteria(policy).length === 0 && <span style={{ color: 'var(--text-muted)' }}>anything</span>}
                        </div>
                      </td>
                      <td>
                        <span className="mono" style={{ fontSize: '12px' }}>{scopeLabel(policy)}</span>
                      </td>
                      <td>
                        <span className={`badge ${policy.status === 'REJECTED' ? 'badge-alert' : 'badge-info'}`}>
                          {policy.status || 'APPROVED'}
                        </span>
                      </td>
                      <td>
                        <span className={`badge badge-${policy.action.toLowerCase()}`}>
                          {policy.action}
                        </span>
                        {policy.expires && (
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                            until {formatTimestamp(policy.expires)}
                          </div>
                        )}
                      </td>
                      <td>
                        <label className="toggle" title={policy.enabled ? 'Disable' : 'Enable'}>
                          <input
                            type="checkbox"
                            aria-label={`${policy.enabled ? 'Disable' : 'Enable'} ${policy.description}`}
                            checked={policy.enabled}
                            onChange={() => handleToggle(policy)}
                          />
                          <span className="toggle-slider" />
                        </label>
                      </td>
                      <td>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {formatTimestamp(policy.created_at)}
                        </span>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <button
                          className="btn btn-ghost btn-sm"
                          style={{ marginRight: '6px' }}
                          onClick={() => setEditing(policy)}
                        >
                          Edit
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => setDeleteConfirm(policy.id)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Create / edit policy modal */}
        {(showEditor || editing) && (
          <div
            className="modal-overlay"
            onClick={() => {
              setShowEditor(false);
              setEditing(null);
            }}
          >
            <div className="modal" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>{editing ? 'Edit Allowlist Policy' : 'Create Allowlist Policy'}</h3>
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => {
                    setShowEditor(false);
                    setEditing(null);
                  }}
                >
                  X
                </button>
              </div>
              <div className="modal-body">
                <AllowlistEditor
                  key={editing?.id || 'new'}
                  initial={editing || undefined}
                  editing={!!editing}
                  onSave={editing ? handleUpdate : handleCreate}
                  onCancel={() => {
                    setShowEditor(false);
                    setEditing(null);
                  }}
                />
              </div>
            </div>
          </div>
        )}

        {/* Delete confirmation modal */}
        {deleteConfirm && (
          <div className="modal-overlay" onClick={() => setDeleteConfirm(null)}>
            <div className="modal" style={{ maxWidth: '400px' }} onClick={(e) => e.stopPropagation()}>
              <div className="modal-body">
                <div className="confirm-dialog">
                  <h3 style={{ marginBottom: '8px', color: 'var(--text-primary)' }}>
                    Delete Policy
                  </h3>
                  <p>
                    Are you sure you want to delete this policy? Events previously
                    matched by this rule will no longer be allowlisted.
                  </p>
                  <div className="btn-group">
                    <button
                      className="btn btn-ghost"
                      onClick={() => setDeleteConfirm(null)}
                    >
                      Cancel
                    </button>
                    <button
                      className="btn btn-danger"
                      onClick={() => handleDelete(deleteConfirm)}
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
