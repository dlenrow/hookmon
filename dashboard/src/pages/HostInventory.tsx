import { useState, useEffect, useCallback } from 'react';
import type { Host } from '../api/types';
import { getHosts } from '../api/client';
import { HostStatus } from '../components/HostStatus';
import { formatRelativeTime, formatTimestamp } from '../utils';

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
            <p>Deploy the hookmon-agent to monitored hosts to see them here.</p>
          </div>
        ) : (
          <div className="host-grid">
            {sortedHosts.map((host) => (
              <div key={host.id} className="card">
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
                    <span className="detail-label">Agent</span>
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
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
