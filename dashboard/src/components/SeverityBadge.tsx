import type { Severity } from '../api/types';

interface SeverityBadgeProps {
  severity: Severity;
}

const SEVERITY_CLASS: Record<Severity, string> = {
  INFO: 'badge-info',
  WARN: 'badge-warn',
  ALERT: 'badge-alert',
  CRITICAL: 'badge-critical',
};

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <span className={`badge ${SEVERITY_CLASS[severity] || 'badge-info'}`}>
      {severity}
    </span>
  );
}
