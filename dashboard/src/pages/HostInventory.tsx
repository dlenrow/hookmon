import { useState, useEffect, useCallback } from 'react';
import type { Host, SensorHealth } from '../api/types';
import { getHosts } from '../api/client';
import { HostStatus } from '../components/HostStatus';
import { formatRelativeTime, formatTimestamp } from '../utils';

/** Colors for the sensor registry's states. */
const SENSOR_COLOR: Record<string, string> = {
  alive: 'var(--status-online)',
  unverifiable: 'var(--status-unresponsive)',
  dead: 'var(--status-offline)',
  failed: 'var(--status-offline)',
};

/**
 * Per-sensor health from the host's latest heartbeat: the bus's sensor
 * registry snapshot.
 */
function SensorHealthList({ sensors }: { sensors?: SensorHealth[] }) {
  if (!sensors || sensors.length === 0) {
    return (
      <div style={{ marginTop: '16px', fontSize: '12px', color: 'var(--text-muted)' }}>
        No sensor report yet (none in the latest heartbeat).
      </div>
    );
  }
  const alive = sensors.filter((s) => s.status === 'alive').length;
  return (
    <div style={{ marginTop: '16px' }} data-testid="sensor-health">
      <div className="detail-label" style={{ marginBottom: '8px' }}>
        Sensors: {alive} of {sensors.length} alive
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 12px' }}>
        {sensors.map((s) => (
          <div
            key={s.name}
            data-testid="sensor"
            data-status={s.status}
            title={s.reason || s.status}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', minWidth: 0 }}
          >
            <span
              className="status-dot"
              style={{ backgroundColor: SENSOR_COLOR[s.status] || 'var(--text-muted)', flex: 'none' }}
            />
            <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {s.name}
            </span>
            {s.status !== 'alive' && (
              <span style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{s.status}</span>
            )}
          </div>
        ))}
      </div>
      {sensors
        .filter((s) => s.status !== 'alive' && s.reason)
        .map((s) => (
          <div key={s.name} style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            {s.name}: {s.reason}
          </div>
        ))}
    </div>
  );
}

export function HostInventory() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadHosts = useCallback(async () => {
    try {
      const data = await getHosts();
      setHosts(data || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load hosts');
    } finally {
      setLoading(false);
    }
  }, []);

  // Load on mount and auto-refresh every 30s
  useEffect(() => {
    loadHosts();
    const interval = setInterval(loadHosts, 30000);
    return () => clearInterval(interval);
  }, [loadHosts]);

  // Sort: online first, then unresponsive, then offline
  const statusOrder = { ONLINE: 0, UNRESPONSIVE: 1, OFFLINE: 2 };
  const sortedHosts = [...hosts].sort((a, b) => {
    const aOrder = statusOrder[a.status] ?? 3;
    const bOrder = statusOrder[b.status] ?? 3;
    if (aOrder !== bOrder) return aOrder - bOrder;
    return a.hostname.localeCompare(b.hostname);
  });

  const onlineCount = hosts.filter((h) => h.status === 'ONLINE').length;
  const totalCount = hosts.length;

  return (
    <>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h2>Host Inventory</h2>
            <p>
              {totalCount} hosts enrolled - {onlineCount} online
            </p>
          </div>
          <button className="btn btn-ghost" onClick={loadHosts}>
            Refresh
          </button>
        </div>
      </div>

      <div className="page-body">
        {error && <div className="error-banner">{error}</div>}

        {loading ? (
          <div className="loading">Loading hosts</div>
        ) : hosts.length === 0 ? (
          <div className="empty-state">
            <h3>No hosts enrolled</h3>
            <p>Enroll a sensor bus (hookmon-bus --enroll-token; see Settings) to see hosts here.</p>
          </div>
        ) : (
          <div className="host-grid">
            {sortedHosts.map((host) => (
              <div key={host.id} className="card" data-testid="host-card" data-host-id={host.id}>
                <div className="card-body">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '15px', marginBottom: '2px' }}>
                        {host.hostname}
                      </div>
                      <div className="mono" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {host.ip_address}
                      </div>
                    </div>
                    <HostStatus status={host.status} />
                  </div>

                  <div className="detail-grid" style={{ gridTemplateColumns: '120px 1fr', gap: '6px 12px' }}>
                    <span className="detail-label">Bus version</span>
                    <span className="detail-value mono">{host.agent_version || '-'}</span>

                    <span className="detail-label">OS</span>
                    <span className="detail-value" style={{ fontSize: '12px' }}>
                      {host.os_info || '-'}
                    </span>

                    <span className="detail-label">Enrolled</span>
                    <span className="detail-value" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {formatTimestamp(host.enrolled_at)}
                    </span>

                    <span className="detail-label">Last Heartbeat</span>
                    <span className="detail-value" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {formatRelativeTime(host.last_heartbeat)}
                    </span>

                    <span className="detail-label">Last Event</span>
                    <span className="detail-value" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {host.last_event_at ? formatRelativeTime(host.last_event_at) : 'None'}
                    </span>
                  </div>

                  <SensorHealthList sensors={host.sensors} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
