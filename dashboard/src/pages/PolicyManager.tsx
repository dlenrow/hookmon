import { useState, useEffect, useCallback } from 'react';
import type { AllowlistEntry } from '../api/types';
import { getPolicies, createPolicy, deletePolicy } from '../api/client';
import { AllowlistEditor } from '../components/AllowlistEditor';
import { formatTimestamp } from '../utils';

export function PolicyManager() {
  const [policies, setPolicies] = useState<AllowlistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const loadPolicies = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getPolicies();
      setPolicies(data || []);
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

  return (
    <>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h2>Policy Manager</h2>
            <p>Manage allowlist entries and security policies</p>
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
            <p>Create allowlist entries to define trusted hook activity.</p>
          </div>
        ) : (
          <div className="card">
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Description</th>
                    <th>Event Types</th>
                    <th>Exe Path</th>
                    <th>Action</th>
                    <th>Enabled</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {policies.map((policy) => (
                    <tr key={policy.id}>
                      <td>
                        <div style={{ maxWidth: '250px' }}>
                          <div style={{ fontWeight: 500 }}>{policy.description || '(no description)'}</div>
                          {policy.created_by && (
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                              by {policy.created_by}
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
                        <span className="mono" style={{ fontSize: '12px' }}>
                          {policy.exe_path || '-'}
                        </span>
                      </td>
                      <td>
                        <span className={`badge badge-${policy.action.toLowerCase()}`}>
                          {policy.action}
                        </span>
                      </td>
                      <td>
                        <span
                          className="status-dot"
                          style={{
                            backgroundColor: policy.enabled ? 'var(--status-online)' : 'var(--text-muted)',
                            boxShadow: policy.enabled ? '0 0 6px var(--status-online)' : 'none',
                          }}
                        />
                      </td>
                      <td>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {formatTimestamp(policy.created_at)}
                        </span>
                      </td>
                      <td>
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

        {/* Create policy modal */}
        {showEditor && (
          <div className="modal-overlay" onClick={() => setShowEditor(false)}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>Create Allowlist Policy</h3>
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => setShowEditor(false)}
                >
                  X
                </button>
              </div>
              <div className="modal-body">
                <AllowlistEditor
                  onSave={handleCreate}
                  onCancel={() => setShowEditor(false)}
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
