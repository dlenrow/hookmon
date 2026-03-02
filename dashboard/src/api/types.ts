/**
 * HookMon API type definitions.
 * These mirror the Go types in pkg/event/event.go.
 */

export type EventType =
  | 'BPF_LOAD'
  | 'BPF_ATTACH'
  | 'LD_PRELOAD'
  | 'SHM_CREATE'
  | 'DLOPEN'
  | 'AGENT_OFFLINE'
  | 'AGENT_RECOVERED';

export type Severity = 'INFO' | 'WARN' | 'ALERT' | 'CRITICAL';

export type PolicyAction = 'ALLOW' | 'ALERT' | 'DENY';

export type HostStatusType = 'ONLINE' | 'UNRESPONSIVE' | 'OFFLINE';

export interface BPFDetail {
  bpf_cmd: number;
  prog_type: number;
  prog_name: string;
  attach_type: number;
  target_fd: number;
  insn_count: number;
  prog_hash: string;
}

export interface PreloadDetail {
  library_path: string;
  library_hash: string;
  target_binary: string;
  set_by: string;
}

export interface SHMDetail {
  shm_name: string;
  size: number;
  pattern: string;
}

export interface DlopenDetail {
  library_path: string;
  library_hash: string;
  flags: number;
}

export interface PolicyResult {
  action: PolicyAction;
  matched_entry_id?: string;
  reason: string;
}

export interface HookEvent {
  id: string;
  timestamp: string;
  host_id: string;
  hostname: string;
  event_type: EventType;
  severity: Severity;
  pid: number;
  ppid: number;
  uid: number;
  gid: number;
  comm: string;
  cmdline: string;
  exe_path: string;
  exe_hash: string;
  cgroup_path: string;
  container_id: string;
  namespace: string;
  bpf_detail?: BPFDetail;
  preload_detail?: PreloadDetail;
  shm_detail?: SHMDetail;
  dlopen_detail?: DlopenDetail;
  policy_result?: PolicyResult;
}

export interface UIDRange {
  min: number;
  max: number;
}

export interface AllowlistEntry {
  id: string;
  created_at: string;
  created_by: string;
  description: string;
  event_types: EventType[];
  exe_hash: string;
  exe_path: string;
  library_hash: string;
  library_path: string;
  prog_name: string;
  prog_type?: number;
  host_pattern: string;
  uid_range?: UIDRange;
  container_image: string;
  action: PolicyAction;
  expires?: string;
  enabled: boolean;
}

export interface Host {
  id: string;
  hostname: string;
  ip_address: string;
  agent_version: string;
  os_info: string;
  status: HostStatusType;
  enrolled_at: string;
  last_heartbeat: string;
  last_event_at?: string;
}

export interface EventQueryParams {
  limit?: number;
  offset?: number;
  host_id?: string;
  event_type?: EventType;
  severity?: Severity;
  since?: string;
  until?: string;
}
