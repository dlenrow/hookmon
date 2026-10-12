import { useNavigate } from 'react-router-dom';
import type { HookEvent, EventType } from '../api/types';
import { SeverityBadge } from './SeverityBadge';
import { AllowlistEventButton } from './AllowlistEventButton';
import { formatTimestamp, bpfProgTypeName } from '../utils';

interface EventCardProps {
  event: HookEvent;
}

export const EVENT_TYPE_CLASS: Record<EventType, string> = {
  BPF_LOAD: 'badge-bpf',
  BPF_ATTACH: 'badge-bpf',
  BPF_INVENTORY: 'badge-bpf',
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

function bpfSummary(event: HookEvent): string {
  const d = event.bpf_detail;
  if (!d) return `BPF ${event.event_type === 'BPF_ATTACH' ? 'attach' : 'load'}`;
  const name = d.prog_name || '(unnamed)';
  const tag = d.prog_hash ? ` tag ${d.prog_hash}` : '';
  const target = d.attach_target ? ` → ${d.attach_target}` : '';
  return `${bpfProgTypeName(d.prog_type)} ${name}${tag}${target}`;
}

export function eventSummary(event: HookEvent): string {
  switch (event.event_type) {
    case 'BPF_LOAD':
    case 'BPF_ATTACH':
      return bpfSummary(event);
    case 'BPF_INVENTORY': {
      const inv = event.bpf_inventory_detail;
      if (inv?.summary) {
        return `Inventory scan: ${inv.prog_count ?? 0} BPF programs loaded`;
      }
      return `Loaded: ${bpfSummary(event)}`;
    }
    case 'EXEC_INJECTION': {
      const d = event.exec_injection_detail;
      if (!d) return 'Exec injection detected';
      if (d.scan_truncated) return 'Environment scan truncated: an LD_* variable may be unscanned';
      const v = d.env_var || 'LD_*';
      return `${v}=${d.library_path}${d.value_truncated ? '… (truncated)' : ''}`;
    }
    case 'SHM_CREATE':
      return event.shm_detail
        ? `SHM: ${event.shm_detail.shm_name} (${event.shm_detail.pattern || 'no pattern'})`
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
        ? `${event.ptrace_detail.request_name} → PID ${event.ptrace_detail.target_pid}${event.ptrace_detail.target_comm ? ` (${event.ptrace_detail.target_comm})` : ''}`
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
      return 'Sensor bus went offline';
    case 'AGENT_RECOVERED':
      return 'Sensor bus recovered';
    default:
      return event.event_type;
  }
}

/**
 * What the server did with the event: the first sighting of a new hook
 * (decided on the New hooks page) or an occurrence of a denied one.
 */
export function DispositionBadge({ event }: { event: HookEvent }) {
  switch (event.policy_result?.disposition) {
    case 'first_sighting':
      return (
        <span className="badge badge-new" data-testid="disposition" data-disposition="first_sighting" style={{ marginLeft: '6px' }}>
          {event.policy_result?.quiet ? 'first sighting (quiet period)' : 'first sighting'}
        </span>
      );
    case 'denied':
      return (
        <span className="badge badge-deny" data-testid="disposition" data-disposition="denied" style={{ marginLeft: '6px' }}>
          denied
        </span>
      );
    default:
      return null;
  }
}

function processLabel(event: HookEvent): string {
  if (event.event_type === 'BPF_INVENTORY' || !event.pid) return '-';
  return `${event.comm} (PID ${event.pid})`;
}

export function EventCard({ event }: EventCardProps) {
  const navigate = useNavigate();

  return (
    <tr
      className="clickable-row"
      data-testid="event-row"
      data-event-id={event.id}
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
          {processLabel(event)}
        </span>
      </td>
      <td style={{ whiteSpace: 'nowrap' }}>
        {event.policy_result && (
          <span className={`badge badge-${event.policy_result.action.toLowerCase()}`}>
            {event.policy_result.action}
          </span>
        )}
        <DispositionBadge event={event} />
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        {event.policy_result?.action !== 'ALLOW' && <AllowlistEventButton event={event} compact />}
      </td>
    </tr>
  );
}
