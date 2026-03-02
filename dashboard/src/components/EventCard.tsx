import { useNavigate } from 'react-router-dom';
import type { HookEvent, EventType } from '../api/types';
import { SeverityBadge } from './SeverityBadge';
import { formatTimestamp } from '../utils';

interface EventCardProps {
  event: HookEvent;
}

const EVENT_TYPE_CLASS: Record<EventType, string> = {
  BPF_LOAD: 'badge-bpf',
  BPF_ATTACH: 'badge-bpf',
  LD_PRELOAD: 'badge-preload',
  SHM_CREATE: 'badge-shm',
  DLOPEN: 'badge-dlopen',
  AGENT_OFFLINE: 'badge-critical',
  AGENT_RECOVERED: 'badge-info',
};

function eventSummary(event: HookEvent): string {
  switch (event.event_type) {
    case 'BPF_LOAD':
    case 'BPF_ATTACH':
      return event.bpf_detail?.prog_name
        ? `BPF program: ${event.bpf_detail.prog_name}`
        : `BPF cmd=${event.bpf_detail?.bpf_cmd ?? 'unknown'}`;
    case 'LD_PRELOAD':
      return event.preload_detail?.library_path
        ? `Library: ${event.preload_detail.library_path}`
        : 'LD_PRELOAD detected';
    case 'SHM_CREATE':
      return event.shm_detail?.shm_name
        ? `SHM: ${event.shm_detail.shm_name}`
        : 'Shared memory created';
    case 'DLOPEN':
      return event.dlopen_detail?.library_path
        ? `dlopen: ${event.dlopen_detail.library_path}`
        : 'dlopen() call detected';
    case 'AGENT_OFFLINE':
      return 'Agent went offline';
    case 'AGENT_RECOVERED':
      return 'Agent recovered';
    default:
      return event.event_type;
  }
}

export function EventCard({ event }: EventCardProps) {
  const navigate = useNavigate();

  return (
    <tr
      className="clickable-row"
      onClick={() => navigate(`/events/${event.id}`)}
    >
      <td style={{ whiteSpace: 'nowrap' }}>
        <span className="mono" style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
          {formatTimestamp(event.timestamp)}
        </span>
      </td>
      <td>
        <span className={`badge ${EVENT_TYPE_CLASS[event.event_type] || 'badge-type'}`}>
          {event.event_type}
        </span>
      </td>
      <td>
        <SeverityBadge severity={event.severity} />
      </td>
      <td>
        <span className="mono">{event.hostname || event.host_id}</span>
      </td>
      <td>
        <span style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
          {eventSummary(event)}
        </span>
      </td>
      <td>
        <span className="mono" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          {event.comm} (PID {event.pid})
        </span>
      </td>
      <td>
        {event.policy_result && (
          <span className={`badge badge-${event.policy_result.action.toLowerCase()}`}>
            {event.policy_result.action}
          </span>
        )}
      </td>
    </tr>
  );
}
