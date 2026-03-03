import { useState } from 'react';
import type { AllowlistEntry, EventType, PolicyAction } from '../api/types';

interface AllowlistEditorProps {
  onSave: (entry: Partial<AllowlistEntry>) => void;
  onCancel: () => void;
  initial?: Partial<AllowlistEntry>;
}

const EVENT_TYPES: EventType[] = [
  'BPF_LOAD',
  'BPF_ATTACH',
  'EXEC_INJECTION',
  'SHM_CREATE',
  'DLOPEN',
  'LINKER_CONFIG',
  'PTRACE_INJECT',
  'LIB_INTEGRITY',
];

const ACTIONS: PolicyAction[] = ['ALLOW', 'ALERT', 'DENY'];

export function AllowlistEditor({ onSave, onCancel, initial }: AllowlistEditorProps) {
  const [description, setDescription] = useState(initial?.description || '');
  const [eventTypes, setEventTypes] = useState<EventType[]>(initial?.event_types || []);
  const [exePath, setExePath] = useState(initial?.exe_path || '');
  const [exeHash, setExeHash] = useState(initial?.exe_hash || '');
  const [libraryPath, setLibraryPath] = useState(initial?.library_path || '');
  const [libraryHash, setLibraryHash] = useState(initial?.library_hash || '');
  const [progName, setProgName] = useState(initial?.prog_name || '');
  const [hostPattern, setHostPattern] = useState(initial?.host_pattern || '');
  const [containerImage, setContainerImage] = useState(initial?.container_image || '');
  const [action, setAction] = useState<PolicyAction>(initial?.action || 'ALLOW');
  const [enabled, setEnabled] = useState(initial?.enabled !== false);
  const [createdBy, setCreatedBy] = useState(initial?.created_by || '');

  function handleEventTypeToggle(et: EventType) {
    setEventTypes((prev) =>
      prev.includes(et) ? prev.filter((t) => t !== et) : [...prev, et]
    );
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSave({
      description,
      event_types: eventTypes.length > 0 ? eventTypes : [],
      exe_path: exePath || '',
      exe_hash: exeHash || '',
      library_path: libraryPath || '',
      library_hash: libraryHash || '',
      prog_name: progName || '',
      host_pattern: hostPattern || '',
      container_image: containerImage || '',
      action,
      enabled,
      created_by: createdBy || '',
    });
  }

  return (
    <form onSubmit={handleSubmit}>
      <div className="form-group">
        <label className="form-label">Description</label>
        <textarea
          className="form-textarea"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Reason for this allowlist entry"
          required
        />
      </div>

      <div className="form-group">
        <label className="form-label">Event Types</label>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          {EVENT_TYPES.map((et) => (
            <label key={et} className="form-checkbox">
              <input
                type="checkbox"
                checked={eventTypes.includes(et)}
                onChange={() => handleEventTypeToggle(et)}
              />
              {et}
            </label>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        <div className="form-group">
          <label className="form-label">Exe Path (glob)</label>
          <input
            type="text"
            className="form-input"
            value={exePath}
            onChange={(e) => setExePath(e.target.value)}
            placeholder="/usr/bin/cilium*"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Exe Hash (SHA256)</label>
          <input
            type="text"
            className="form-input"
            value={exeHash}
            onChange={(e) => setExeHash(e.target.value)}
            placeholder="sha256:..."
          />
        </div>

        <div className="form-group">
          <label className="form-label">Library Path (glob)</label>
          <input
            type="text"
            className="form-input"
            value={libraryPath}
            onChange={(e) => setLibraryPath(e.target.value)}
            placeholder="/usr/lib/*.so"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Library Hash (SHA256)</label>
          <input
            type="text"
            className="form-input"
            value={libraryHash}
            onChange={(e) => setLibraryHash(e.target.value)}
            placeholder="sha256:..."
          />
        </div>

        <div className="form-group">
          <label className="form-label">BPF Program Name</label>
          <input
            type="text"
            className="form-input"
            value={progName}
            onChange={(e) => setProgName(e.target.value)}
            placeholder="trace_tcp_connect"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Host Pattern (glob)</label>
          <input
            type="text"
            className="form-input"
            value={hostPattern}
            onChange={(e) => setHostPattern(e.target.value)}
            placeholder="web-prod-*"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Container Image</label>
          <input
            type="text"
            className="form-input"
            value={containerImage}
            onChange={(e) => setContainerImage(e.target.value)}
            placeholder="docker.io/cilium/cilium:*"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Created By</label>
          <input
            type="text"
            className="form-input"
            value={createdBy}
            onChange={(e) => setCreatedBy(e.target.value)}
            placeholder="admin@company.com"
          />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        <div className="form-group">
          <label className="form-label">Action</label>
          <select
            className="form-select"
            value={action}
            onChange={(e) => setAction(e.target.value as PolicyAction)}
          >
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </div>

        <div className="form-group" style={{ display: 'flex', alignItems: 'flex-end' }}>
          <label className="form-checkbox">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            Enabled
          </label>
        </div>
      </div>

      <div className="modal-footer" style={{ padding: '16px 0 0', borderTop: 'none' }}>
        <button type="button" className="btn btn-ghost" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className="btn btn-primary">
          Save Policy
        </button>
      </div>
    </form>
  );
}
