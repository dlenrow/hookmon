import type { HostStatusType } from '../api/types';

interface HostStatusProps {
  status: HostStatusType;
  showLabel?: boolean;
}

const STATUS_CLASS: Record<HostStatusType, string> = {
  ONLINE: 'online',
  UNRESPONSIVE: 'unresponsive',
  OFFLINE: 'offline',
};

const STATUS_LABEL: Record<HostStatusType, string> = {
  ONLINE: 'Online',
  UNRESPONSIVE: 'Unresponsive',
  OFFLINE: 'Offline',
};

export function HostStatus({ status, showLabel = true }: HostStatusProps) {
  const cssClass = STATUS_CLASS[status] || 'offline';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
      <span className={`status-dot ${cssClass}`} />
      {showLabel && (
        <span style={{ fontSize: '13px' }}>{STATUS_LABEL[status] || status}</span>
      )}
    </span>
  );
}
