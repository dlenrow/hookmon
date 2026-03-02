import { useState, useEffect, useCallback } from 'react';
import { Routes, Route, NavLink, Navigate } from 'react-router-dom';
import type { Severity, HookEvent } from './api/types';
import { getEvents, connectWebSocket } from './api/client';
import { EventFeed } from './pages/EventFeed';
import { PolicyManager } from './pages/PolicyManager';
import { HostInventory } from './pages/HostInventory';
import { Investigation } from './pages/Investigation';
import { Settings } from './pages/Settings';

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
  const [wsConnected, setWsConnected] = useState(false);
  const [liveEvents, setLiveEvents] = useState<HookEvent[]>([]);

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

  const handleWsStatus = useCallback((connected: boolean) => {
    setWsConnected(connected);
  }, []);

  useEffect(() => {
    const ws = connectWebSocket(handleWsEvent, handleWsStatus);
    return () => ws.close();
  }, [handleWsEvent, handleWsStatus]);

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
          <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>
            <span className="nav-icon">S</span>
            Settings
          </NavLink>
        </nav>

        <div className="sidebar-stats">
          <div
            className={`ws-status ${wsConnected ? 'connected' : 'disconnected'}`}
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
            {wsConnected ? 'Live' : 'Disconnected'}
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
            element={<EventFeed liveEvents={liveEvents} wsConnected={wsConnected} />}
          />
          <Route path="/events/:id" element={<Investigation />} />
          <Route path="/hosts" element={<HostInventory />} />
          <Route path="/policies" element={<PolicyManager />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
