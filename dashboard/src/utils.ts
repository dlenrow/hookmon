/**
 * Format an ISO timestamp into a human-readable local time string.
 */
export function formatTimestamp(iso: string): string {
  try {
    const date = new Date(iso);
    return date.toLocaleString('en-US', {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return iso;
  }
}

/**
 * Format a full ISO timestamp with date and milliseconds.
 */
export function formatTimestampFull(iso: string): string {
  try {
    const date = new Date(iso);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    } as Intl.DateTimeFormatOptions);
  } catch {
    return iso;
  }
}

/**
 * Format a relative time string (e.g., "3m ago", "2h ago").
 */
export function formatRelativeTime(iso: string): string {
  try {
    const date = new Date(iso);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffSec = Math.floor(diffMs / 1000);

    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return `${diffHour}h ago`;
    const diffDay = Math.floor(diffHour / 24);
    return `${diffDay}d ago`;
  } catch {
    return iso;
  }
}

/**
 * Truncate a string to a maximum length, adding ellipsis if truncated.
 */
export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}

/**
 * Truncate a SHA256 hash for display.
 */
export function truncateHash(hash: string): string {
  if (!hash) return '';
  if (hash.startsWith('sha256:')) {
    return `sha256:${hash.slice(7, 19)}...`;
  }
  if (hash.length > 16) {
    return `${hash.slice(0, 12)}...`;
  }
  return hash;
}

/**
 * Map BPF program type number to a human-readable name.
 */
export function bpfProgTypeName(progType: number): string {
  const names: Record<number, string> = {
    0: 'UNSPEC',
    1: 'SOCKET_FILTER',
    2: 'KPROBE',
    3: 'SCHED_CLS',
    4: 'SCHED_ACT',
    5: 'TRACEPOINT',
    6: 'XDP',
    7: 'PERF_EVENT',
    8: 'CGROUP_SKB',
    9: 'CGROUP_SOCK',
    10: 'LWT_IN',
    11: 'LWT_OUT',
    12: 'LWT_XMIT',
    13: 'SOCK_OPS',
    14: 'SK_SKB',
    15: 'CGROUP_DEVICE',
    16: 'SK_MSG',
    17: 'RAW_TRACEPOINT',
    18: 'CGROUP_SOCK_ADDR',
    19: 'LWT_SEG6LOCAL',
    20: 'LIRC_MODE2',
    21: 'SK_REUSEPORT',
    22: 'FLOW_DISSECTOR',
    23: 'CGROUP_SYSCTL',
    24: 'RAW_TRACEPOINT_WRITABLE',
    25: 'CGROUP_SOCKOPT',
    26: 'TRACING',
    27: 'STRUCT_OPS',
    28: 'EXT',
    29: 'LSM',
    30: 'SK_LOOKUP',
    31: 'SYSCALL',
  };
  return names[progType] || `TYPE_${progType}`;
}

/**
 * Map BPF command number to a human-readable name.
 */
export function bpfCmdName(cmd: number): string {
  const names: Record<number, string> = {
    0: 'MAP_CREATE',
    1: 'MAP_LOOKUP_ELEM',
    2: 'MAP_UPDATE_ELEM',
    3: 'MAP_DELETE_ELEM',
    4: 'MAP_GET_NEXT_KEY',
    5: 'PROG_LOAD',
    6: 'OBJ_PIN',
    7: 'OBJ_GET',
    8: 'PROG_ATTACH',
    9: 'PROG_DETACH',
    10: 'PROG_TEST_RUN',
    11: 'PROG_GET_NEXT_ID',
    12: 'MAP_GET_NEXT_ID',
    13: 'PROG_GET_FD_BY_ID',
    14: 'MAP_GET_FD_BY_ID',
    15: 'OBJ_GET_INFO_BY_FD',
  };
  return names[cmd] || `CMD_${cmd}`;
}
