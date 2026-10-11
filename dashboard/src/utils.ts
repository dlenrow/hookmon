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
 * Map a BPF command number to its name. The bpf_syscall sensor reports
 * only these commands. BPF_INVENTORY events carry 0, which there means no
 * syscall (the program was found by an inventory scan), not MAP_CREATE.
 */
export function bpfCmdName(cmd: number): string {
  const names: Record<number, string> = {
    5: 'BPF_PROG_LOAD',
    8: 'BPF_PROG_ATTACH',
    17: 'BPF_RAW_TRACEPOINT_OPEN',
    28: 'BPF_LINK_CREATE',
  };
  return names[cmd] || `CMD_${cmd}`;
}

/**
 * What a ptrace request does to the tracee. The ptrace sensor reports
 * attaching and writing memory or registers.
 */
export function ptraceRequestDescription(name: string): string {
  const desc: Record<string, string> = {
    PTRACE_ATTACH: 'attach to a running process',
    PTRACE_SEIZE: 'attach to a running process without stopping it',
    PTRACE_POKETEXT: "write to the tracee's code",
    PTRACE_POKEDATA: "write to the tracee's data",
    PTRACE_POKEUSER: "write to the tracee's USER area (registers)",
    PTRACE_SETREGS: "overwrite the tracee's registers",
    PTRACE_SETREGSET: 'overwrite a tracee register set',
  };
  return desc[name] || '';
}

/**
 * What the shm sensor's pattern for a /dev/shm name means.
 */
export function shmPatternDescription(pattern: string): string {
  const desc: Record<string, string> = {
    bpftime: 'bpftime userspace eBPF runtime',
    bpf_related: 'name mentions bpf, ebpf or libbpf',
    unknown: 'no known pattern',
  };
  return desc[pattern] || '';
}

/**
 * The port of a "host:port" listener address ("[::]:9443" gives "9443").
 */
export function addrPort(addr: string): string {
  const i = addr.lastIndexOf(':');
  return i >= 0 ? addr.slice(i + 1) : '';
}
