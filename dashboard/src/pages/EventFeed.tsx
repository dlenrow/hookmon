import { useState, useEffect, useRef, useCallback } from 'react';
import type { HookEvent, EventType, Severity } from '../api/types';
import { getEvents } from '../api/client';
import { EventCard } from '../components/EventCard';

interface EventFeedProps {
  liveEvents: HookEvent[];
  wsConnected: boolean;
}

const EVENT_TYPES: EventType[] = [
  'BPF_LOAD',
  'BPF_ATTACH',
  'LD_PRELOAD',
  'SHM_CREATE',
  'DLOPEN',
  'AGENT_OFFLINE',
  'AGENT_RECOVERED',
];

const SEVERITIES: Severity[] = ['INFO', 'WARN', 'ALERT', 'CRITICAL'];

export function EventFeed({ liveEvents, wsConnected }: EventFeedProps) {
  const [historicalEvents, setHistoricalEvents] = useState<HookEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Filters
  const [filterEventType, setFilterEventType] = useState<string>('');
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [filterHost, setFilterHost] = useState('');

  const tableEndRef = useRef<HTMLDivElement>(null);

  // Load historical events
  useEffect(() => {
    let cancelled = false;

    async function loadEvents() {
      setLoading(true);
      setError(null);
      try {
        const events = await getEvents({
          limit: 200,
          event_type: filterEventType ? (filterEventType as EventType) : undefined,
          severity: filterSeverity ? (filterSeverity as Severity) : undefined,
          host_id: filterHost || undefined,
        });
        if (!cancelled) {
          setHistoricalEvents(events);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load events');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadEvents();
    return () => { cancelled = true; };
  }, [filterEventType, filterSeverity, filterHost]);

  // Auto-scroll to bottom on new live events
  useEffect(() => {
    if (autoScroll && tableEndRef.current) {
      tableEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [liveEvents, autoScroll]);

  // Merge live events with historical, applying filters
  const allEvents = useCallback(() => {
    const merged = [...liveEvents, ...historicalEvents];

    // Deduplicate by ID
    const seen = new Set<string>();
    const unique: HookEvent[] = [];
    for (const evt of merged) {
      if (!seen.has(evt.id)) {
        seen.add(evt.id);
        unique.push(evt);
      }
    }

    // Apply client-side filters for live events
    return unique.filter((evt) => {
      if (filterEventType && evt.event_type !== filterEventType) return false;
      if (filterSeverity && evt.severity !== filterSeverity) return false;
      if (filterHost && !evt.hostname.toLowerCase().includes(filterHost.toLowerCase()) && evt.host_id !== filterHost) return false;
      return true;
    });
  }, [liveEvents, historicalEvents, filterEventType, filterSeverity, filterHost]);

  const filteredEvents = allEvents();

  return (
    <>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h2>Event Feed</h2>
            <p>Real-time stream of hook detection events across all monitored hosts</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            {wsConnected && (
              <div className="live-indicator">
                <span className="live-dot" />
                LIVE
              </div>
            )}
            <label className="form-checkbox" style={{ fontSize: '12px' }}>
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
              />
              Auto-scroll
            </label>
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Filter bar */}
        <div className="filter-bar">
          <select
            className="form-select"
            value={filterEventType}
            onChange={(e) => setFilterEventType(e.target.value)}
          >
            <option value="">All Event Types</option>
            {EVENT_TYPES.map((et) => (
              <option key={et} value={et}>{et}</option>
            ))}
          </select>

          <select
            className="form-select"
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
          >
            <option value="">All Severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>

          <input
            type="text"
            className="form-input"
            placeholder="Filter by host..."
            value={filterHost}
            onChange={(e) => setFilterHost(e.target.value)}
            style={{ width: '200px' }}
          />

          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            {filteredEvents.length} events
          </span>
        </div>

        {error && <div className="error-banner">{error}</div>}

        {loading ? (
          <div className="loading">Loading events</div>
        ) : filteredEvents.length === 0 ? (
          <div className="empty-state">
            <h3>No events found</h3>
            <p>Events will appear here when agents detect hook activity.</p>
          </div>
        ) : (
          <div className="card">
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Host</th>
                    <th>Summary</th>
                    <th>Process</th>
                    <th>Policy</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((evt) => (
                    <EventCard key={evt.id} event={evt} />
                  ))}
                </tbody>
              </table>
            </div>
            <div ref={tableEndRef} />
          </div>
        )}
      </div>
    </>
  );
}
