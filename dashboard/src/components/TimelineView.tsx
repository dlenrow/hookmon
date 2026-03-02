import { useNavigate } from 'react-router-dom';
import type { HookEvent } from '../api/types';
import { SeverityBadge } from './SeverityBadge';
import { formatTimestamp } from '../utils';

interface TimelineViewProps {
  events: HookEvent[];
  activeEventId?: string;
}

export function TimelineView({ events, activeEventId }: TimelineViewProps) {
  const navigate = useNavigate();

  if (events.length === 0) {
    return (
      <div className="empty-state">
        <p>No events in timeline</p>
      </div>
    );
  }

  return (
    <div style={{ position: 'relative', paddingLeft: '24px' }}>
      {/* Vertical line */}
      <div
        style={{
          position: 'absolute',
          left: '7px',
          top: '4px',
          bottom: '4px',
          width: '2px',
          backgroundColor: 'var(--border-primary)',
        }}
      />

      {events.map((evt) => {
        const isActive = evt.id === activeEventId;
        return (
          <div
            key={evt.id}
            style={{
              position: 'relative',
              paddingBottom: '16px',
              cursor: 'pointer',
              opacity: isActive ? 1 : 0.7,
            }}
            onClick={() => navigate(`/events/${evt.id}`)}
          >
            {/* Dot */}
            <div
              style={{
                position: 'absolute',
                left: '-21px',
                top: '6px',
                width: '12px',
                height: '12px',
                borderRadius: '50%',
                backgroundColor: isActive
                  ? 'var(--accent)'
                  : 'var(--border-primary)',
                border: isActive
                  ? '2px solid var(--accent)'
                  : '2px solid var(--bg-surface)',
              }}
            />

            <div
              style={{
                padding: '8px 12px',
                backgroundColor: isActive
                  ? 'rgba(59, 130, 246, 0.08)'
                  : 'transparent',
                borderRadius: 'var(--radius)',
                border: isActive
                  ? '1px solid rgba(59, 130, 246, 0.2)'
                  : '1px solid transparent',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  marginBottom: '4px',
                }}
              >
                <SeverityBadge severity={evt.severity} />
                <span
                  className="mono"
                  style={{ fontSize: '11px', color: 'var(--text-muted)' }}
                >
                  {formatTimestamp(evt.timestamp)}
                </span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
                {evt.event_type} - {evt.comm} (PID {evt.pid})
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
