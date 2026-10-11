import { useState, useEffect, useCallback } from 'react';
import { Routes, Route, NavLink, Navigate } from 'react-router-dom';
import type { Severity, HookEvent } from './api/types';
import { getEvents, connectWebSocket } from './api/client';
import type { WebSocketState } from './api/client';
import { EventFeed } from './pages/EventFeed';
import { PolicyManager } from './pages/PolicyManager';
import { PendingApproval } from './pages/PendingApproval';
import { HostInventory } from './pages/HostInventory';
import { Investigation } from './pages/Investigation';
import { Settings } from './pages/Settings';

const WS_LABEL: Record<WebSocketState, string> = {
  live: 'Live',
  reconnecting: 'Disconnected, retrying',
  'no-token': 'No API token (see Settings)',
};

interface SeverityCounts {
  INFO: number;
  WARN: number;
  ALERT: number;
  CRITICAL: number;
}

export function App() {
  const [severityCounts, setSeverityCounts] = useState<SeverityCounts>({
    INFO: 0,
    WARN: 0,
    ALERT: 0,
    CRITICAL: 0,
  });
  const [wsState, setWsState] = useState<WebSocketState>('reconnecting');
  const [resync, setResync] = useState(0);
  const [liveEvents, setLiveEvents] = useState<HookEvent[]>([]);
  const wsConnected = wsState === 'live';

  // Fetch initial severity counts from recent events
  useEffect(() => {
    let cancelled = false;

    async function fetchCounts() {
      try {
        const events = await getEvents({ limit: 500 });
        if (cancelled) return;

        const counts: SeverityCounts = { INFO: 0, WARN: 0, ALERT: 0, CRITICAL: 0 };
        for (const evt of events) {
          if (evt.severity in counts) {
            counts[evt.severity as Severity]++;
          }
        }
        setSeverityCounts(counts);
      } catch {
        // API might not be available yet
      }
    }

    fetchCounts();
    return () => { cancelled = true; };
  }, []);

  // Set up WebSocket for live events and severity count updates
  const handleWsEvent = useCallback((event: HookEvent) => {
    setLiveEvents((prev) => [event, ...prev].slice(0, 1000));
    setSeverityCounts((prev) => ({
      ...prev,
      [event.severity]: (prev[event.severity as Severity] || 0) + 1,
    }));
  }, []);

  // Each (re)connect starts a new feed; pages reload history to cover the gap.
  const handleWsState = useCallback((state: WebSocketState) => {
    setWsState(state);
    if (state === 'live') {
      setResync((n) => n + 1);
    }
  }, []);

  useEffect(() => {
    const ws = connectWebSocket(handleWsEvent, handleWsState);
    return () => ws.close();
  }, [handleWsEvent, handleWsState]);

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <h1>HookMon</h1>
          <div className="logo-sub">Security Dashboard</div>
        </div>

        <nav className="sidebar-nav">
          <NavLink to="/events" className={({ isActive }) => isActive ? 'active' : ''}>
            <span className="nav-icon">E</span>
            Events
          </NavLink>
          <NavLink to="/hosts" className={({ isActive }) => isActive ? 'active' : ''}>
            <span className="nav-icon">H</span>
            Hosts
          </NavLink>
          <NavLink to="/policies" className={({ isActive }) => isActive ? 'active' : ''}>
            <span className="nav-icon">P</span>
            Policies
          </NavLink>
          <NavLink to="/pending" className={({ isActive }) => isActive ? 'active' : ''}>
            <span className="nav-icon">A</span>
            Pending Approval
          </NavLink>
          <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>
            <span className="nav-icon">S</span>
            Settings
          </NavLink>
        </nav>

        <div className="sidebar-stats">
          <div
            className={`ws-status ${wsConnected ? 'connected' : 'disconnected'}`}
            data-testid="ws-status"
            data-state={wsState}
            style={{ marginBottom: '12px' }}
          >
            <span
              className="status-dot"
              style={{
                backgroundColor: wsConnected ? 'var(--status-online)' : 'var(--status-offline)',
                boxShadow: wsConnected
                  ? '0 0 6px var(--status-online)'
                  : '0 0 6px var(--status-offline)',
              }}
            />
            {WS_LABEL[wsState]}
          </div>
          <div className="severity-counts">
            <span className="severity-count info">
              {severityCounts.INFO} INFO
            </span>
            <span className="severity-count warn">
              {severityCounts.WARN} WARN
            </span>
            <span className="severity-count alert">
              {severityCounts.ALERT} ALERT
            </span>
            <span className="severity-count critical">
              {severityCounts.CRITICAL} CRIT
            </span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Navigate to="/events" replace />} />
          <Route
            path="/events"
            element={<EventFeed liveEvents={liveEvents} wsConnected={wsConnected} resync={resync} />}
          />
          <Route path="/events/:id" element={<Investigation />} />
          <Route path="/hosts" element={<HostInventory />} />
          <Route path="/policies" element={<PolicyManager />} />
          <Route path="/pending" element={<PendingApproval />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
