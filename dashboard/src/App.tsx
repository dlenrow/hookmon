import { useState, useEffect, useCallback, useRef } from 'react';
import { Routes, Route, NavLink, Navigate } from 'react-router-dom';
import type { Severity, HookEvent } from './api/types';
import { getEvents, getPolicies, connectWebSocket } from './api/client';
import type { WebSocketState } from './api/client';
import { EventFeed } from './pages/EventFeed';
import { PolicyManager } from './pages/PolicyManager';
import { NewHooks } from './pages/NewHooks';
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
  // New hooks waiting for a decision (PENDING entries), for the navigation.
  const [newHooks, setNewHooks] = useState<number | null>(null);
  // Live first sightings received so far. The New hooks page compares it
  // with the value when its list loaded, to announce hooks that arrived.
  const [firstSightings, setFirstSightings] = useState(0);
  const countTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refreshNewHooks = useCallback(async () => {
    try {
      const pending = await getPolicies('PENDING');
      setNewHooks((pending || []).length);
    } catch {
      // API might not be available yet
    }
  }, []);

  useEffect(() => {
    refreshNewHooks();
    const t = setInterval(refreshNewHooks, 60_000);
    return () => {
      clearInterval(t);
      if (countTimer.current) clearTimeout(countTimer.current);
    };
  }, [refreshNewHooks]);

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
    if (event.policy_result?.disposition === 'first_sighting') {
      setFirstSightings((n) => n + 1);
      // A rollout can bring many at once: count them once it settles.
      if (countTimer.current) clearTimeout(countTimer.current);
      countTimer.current = setTimeout(refreshNewHooks, 2_000);
    }
    setSeverityCounts((prev) => ({
      ...prev,
      [event.severity]: (prev[event.severity as Severity] || 0) + 1,
    }));
  }, [refreshNewHooks]);

  // resync changes each time the live feed starts, and once more if it
  // cannot start at first (no token, or the first connection failed). Pages
  // load history when it changes: the first load waits for the feed, so no
  // event falls between the two and history is fetched once, and each
  // reconnect reloads to cover the gap.
  const firstWsState = useRef(true);
  const handleWsState = useCallback((state: WebSocketState) => {
    setWsState(state);
    if (state === 'live' || firstWsState.current) {
      setResync((n) => n + 1);
    }
    firstWsState.current = false;
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
          <NavLink to="/new-hooks" className={({ isActive }) => isActive ? 'active' : ''}>
            <span className="nav-icon">N</span>
            New hooks
            {newHooks !== null && newHooks > 0 && (
              <span className="nav-count" data-testid="new-hooks-count">{newHooks}</span>
            )}
          </NavLink>
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
          <Route path="/" element={<Navigate to="/new-hooks" replace />} />
          <Route
            path="/new-hooks"
            element={<NewHooks onChanged={refreshNewHooks} arrivals={firstSightings} />}
          />
          <Route
            path="/events"
            element={<EventFeed liveEvents={liveEvents} wsConnected={wsConnected} resync={resync} />}
          />
          <Route path="/events/:id" element={<Investigation />} />
          <Route path="/hosts" element={<HostInventory />} />
          <Route path="/policies" element={<PolicyManager />} />
          <Route path="/pending" element={<Navigate to="/new-hooks" replace />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
