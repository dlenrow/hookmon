import { useState } from 'react';
import { Link } from 'react-router-dom';
import type { AllowlistEntry, HookEvent } from '../api/types';
import { allowlistEvent } from '../api/client';

interface AllowlistEventButtonProps {
  event: HookEvent;
  /** Smaller button, for a table row. */
  compact?: boolean;
  onCreated?: (entry: AllowlistEntry) => void;
}

/** Host status events have nothing to allowlist. */
export function canAllowlist(event: HookEvent): boolean {
  return event.event_type !== 'AGENT_OFFLINE' && event.event_type !== 'AGENT_RECOVERED';
}

/**
 * "Allowlist this event": creates an ALLOW entry from the event on the
 * server, scoped to the fleet or to the event's host. The entry matches
 * exactly the events with this event's learning-mode key.
 */
export function AllowlistEventButton({ event, compact, onCreated }: AllowlistEventButtonProps) {
  const [open, setOpen] = useState(false);
  const [scope, setScope] = useState<'fleet' | 'host'>(event.host_id ? 'host' : 'fleet');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<AllowlistEntry | null>(null);

  if (!canAllowlist(event)) return null;

  function close() {
    setOpen(false);
    setError(null);
    setCreated(null);
    setDescription('');
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const entry = await allowlistEvent(event.id, scope, description.trim() || undefined);
      setCreated(entry);
      onCreated?.(entry);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to allowlist the event');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        className={`btn btn-ghost ${compact ? 'btn-sm' : ''}`}
        onClick={(e) => {
          e.stopPropagation();
          setOpen(true);
        }}
      >
        Allowlist
      </button>

      {open && (
        <div
          className="modal-overlay"
          onClick={(e) => {
            e.stopPropagation();
            close();
          }}
        >
          <div className="modal" style={{ maxWidth: '520px' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Allowlist this event</h3>
              <button className="btn btn-ghost btn-sm" onClick={close}>
                X
              </button>
            </div>
            <div className="modal-body">
              {created ? (
                <div data-testid="allowlist-created">
                  <p style={{ fontSize: '13px', marginBottom: '12px' }}>
                    Created ALLOW entry <span className="mono">{created.id}</span>
                    {created.host_id ? ` for host ${created.host_id}` : ' for the fleet'}. It applies to the next
                    matching event.
                  </p>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                    {created.description}
                  </p>
                  <div className="modal-footer" style={{ padding: 0, borderTop: 'none' }}>
                    <Link to="/policies" className="btn btn-ghost" onClick={close}>
                      View policies
                    </Link>
                    <button className="btn btn-primary" onClick={close}>
                      Done
                    </button>
                  </div>
                </div>
              ) : (
                <form onSubmit={submit}>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                    Creates an ALLOW entry that matches exactly the events like this one: the same event type
                    ({event.event_type}), the same binary hash, the same subject (such as the BPF program tag or
                    the library hash), and the same container context.
                  </p>
                  <div className="form-group">
                    <label className="form-label">Scope</label>
                    <label className="form-checkbox" style={{ marginBottom: '6px' }}>
                      <input
                        type="radio"
                        name="scope"
                        checked={scope === 'host'}
                        onChange={() => setScope('host')}
                        disabled={!event.host_id}
                      />
                      This host only ({event.hostname || event.host_id || 'unknown'})
                    </label>
                    <label className="form-checkbox">
                      <input type="radio" name="scope" checked={scope === 'fleet'} onChange={() => setScope('fleet')} />
                      Every host (fleet)
                    </label>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Description (optional)</label>
                    <input
                      type="text"
                      className="form-input"
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Why this is expected"
                    />
                  </div>
                  {error && <div className="error-banner">{error}</div>}
                  <div className="modal-footer" style={{ padding: 0, borderTop: 'none' }}>
                    <button type="button" className="btn btn-ghost" onClick={close}>
                      Cancel
                    </button>
                    <button type="submit" className="btn btn-primary" disabled={busy}>
                      {busy ? 'Saving' : 'Create ALLOW entry'}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
