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
  EXEC_INJECTION: 'badge-exec-injection',
  SHM_CREATE: 'badge-shm',
  DLOPEN: 'badge-dlopen',
  LINKER_CONFIG: 'badge-linker-config',
  PTRACE_INJECT: 'badge-ptrace',
  LIB_INTEGRITY: 'badge-lib-integrity',
  AGENT_OFFLINE: 'badge-critical',
  AGENT_RECOVERED: 'badge-info',
  ELF_RPATH: 'badge-elf-rpath',
};

function eventSummary(event: HookEvent): string {
  switch (event.event_type) {
    case 'BPF_LOAD':
    case 'BPF_ATTACH':
      return event.bpf_detail?.prog_name
        ? `BPF program: ${event.bpf_detail.prog_name}`
        : `BPF cmd=${event.bpf_detail?.bpf_cmd ?? 'unknown'}`;
    case 'EXEC_INJECTION':
      return event.exec_injection_detail?.library_path
        ? `Library: ${event.exec_injection_detail.library_path}`
        : 'Exec injection detected';
    case 'SHM_CREATE':
      return event.shm_detail?.shm_name
        ? `SHM: ${event.shm_detail.shm_name}`
        : 'Shared memory created';
    case 'DLOPEN':
      return event.dlopen_detail?.library_path
        ? `dlopen: ${event.dlopen_detail.library_path}`
        : 'dlopen() call detected';
    case 'LINKER_CONFIG':
      return event.linker_config_detail?.file_path
        ? `Config: ${event.linker_config_detail.file_path} (${event.linker_config_detail.operation})`
        : 'Linker config modified';
    case 'PTRACE_INJECT':
      return event.ptrace_detail?.request_name
        ? `${event.ptrace_detail.request_name} → PID ${event.ptrace_detail.target_pid}`
        : 'Ptrace injection detected';
    case 'LIB_INTEGRITY':
      return event.lib_integrity_detail?.library_path
        ? `${event.lib_integrity_detail.operation}: ${event.lib_integrity_detail.library_path}`
        : 'Library modified';
    case 'ELF_RPATH':
      return event.elf_rpath_detail
        ? `RPATH risk: ${event.elf_rpath_detail.highest_risk} in ${event.exe_path}`
        : 'Suspicious ELF RPATH detected';
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
