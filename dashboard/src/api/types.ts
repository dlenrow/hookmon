/**
 * HookMon API type definitions.
 * These mirror the Go types in pkg/event/event.go and server/api.
 */

export type EventType =
  | 'BPF_LOAD'
  | 'BPF_ATTACH'
  | 'BPF_INVENTORY'
  | 'EXEC_INJECTION'
  | 'SHM_CREATE'
  | 'DLOPEN'
  | 'LINKER_CONFIG'
  | 'PTRACE_INJECT'
  | 'LIB_INTEGRITY'
  | 'AGENT_OFFLINE'
  | 'AGENT_RECOVERED'
  | 'ELF_RPATH';

export type Severity = 'INFO' | 'WARN' | 'ALERT' | 'CRITICAL';

export type PolicyAction = 'ALLOW' | 'ALERT' | 'DENY';

export type EntryStatus = 'APPROVED' | 'PENDING' | 'REJECTED';

export type HostStatusType = 'ONLINE' | 'UNRESPONSIVE' | 'OFFLINE';

/**
 * BPF_LOAD and BPF_ATTACH describe the program a bpf() call loaded or
 * attached; each per-program BPF_INVENTORY event describes one loaded
 * program (bpf_cmd is then 0: no syscall was seen).
 */
export interface BPFDetail {
  bpf_cmd: number;
  prog_type: number;
  prog_name: string;
  attach_type: number;
  target_fd: number;
  insn_count: number;
  /** The kernel's program tag: 16 hex digits, as bpftool prog show prints it. */
  prog_hash: string;
  prog_id?: number;
  load_time?: string;
  created_by_uid?: number;
  /** Tracepoint name of a BPF_RAW_TRACEPOINT_OPEN. */
  attach_target?: string;
}

export interface BPFInventoryDetail {
  scan_id: string;
  summary: boolean;
  prog_count?: number;
  by_type?: Record<string, number>;
}

export interface ExecInjectionDetail {
  library_path: string;
  library_hash: string;
  target_binary: string;
  set_by: string;
  env_var?: string;
  /** The sensor stopped before the end of the environment; an LD_* variable may be in the part it did not scan. */
  scan_truncated?: boolean;
  /** The variable's value was longer than the sensor captures; library_path holds only its start. */
  value_truncated?: boolean;
}

export interface SHMDetail {
  shm_name: string;
  size: number;
  /** bpftime, bpf_related or unknown. */
  pattern: string;
}

export interface DlopenDetail {
  library_path: string;
  library_hash: string;
  flags: number;
}

export interface LinkerConfigDetail {
  file_path: string;
  operation: string;
  old_hash?: string;
  new_hash?: string;
}

export interface PtraceDetail {
  request: number;
  request_name: string;
  target_pid: number;
  target_comm: string;
  addr?: number;
}

export interface LibIntegrityDetail {
  library_path: string;
  operation: string;
  old_hash?: string;
  new_hash?: string;
  in_ld_cache: boolean;
}

export type RpathRisk = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface RpathEntry {
  path: string;
  risk: RpathRisk;
  reason: string;
  exists: boolean;
  is_rpath: boolean;
}

export interface ElfRpathDetail {
  has_rpath: boolean;
  has_runpath: boolean;
  rpath_raw?: string;
  runpath_raw?: string;
  entries: RpathEntry[] | null;
  highest_risk: RpathRisk;
  uses_origin: boolean;
  uses_deprecated: boolean;
  is_setuid: boolean;
}

/**
 * What the server did with a hook event (the first-sighting model):
 * - first_sighting: no decided entry matched and this event created the
 *   PENDING entry for its key. Stored, shown, sent to connectors.
 * - repeat: a PENDING entry for the key already existed. Counted on it only.
 * - allowed: matched an ALLOW entry. Dropped.
 * - denied: matched an ALERT or DENY entry (a rejected hook). Stored and
 *   alerted every time.
 * - lifecycle: AGENT_OFFLINE or AGENT_RECOVERED.
 * Only first_sighting, denied and lifecycle events are stored, so the API
 * and the live feed never carry repeat or allowed.
 */
export type Disposition = 'first_sighting' | 'repeat' | 'allowed' | 'denied' | 'lifecycle';

export interface PolicyResult {
  action: PolicyAction;
  matched_entry_id?: string;
  reason: string;
  disposition?: Disposition;
  /** The PENDING entry for the event's key, when there is one. */
  candidate_id?: string;
  /** A first sighting during a quiet period: not sent to alert connectors. */
  quiet?: boolean;
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
  exec_injection_detail?: ExecInjectionDetail;
  shm_detail?: SHMDetail;
  dlopen_detail?: DlopenDetail;
  linker_config_detail?: LinkerConfigDetail;
  ptrace_detail?: PtraceDetail;
  lib_integrity_detail?: LibIntegrityDetail;
  elf_rpath_detail?: ElfRpathDetail;
  bpf_inventory_detail?: BPFInventoryDetail;
  policy_result?: PolicyResult;
}

export interface UIDRange {
  min: number;
  max: number;
}

/** The learning-mode dedupe key: what was loaded or changed. */
export interface LearnedKey {
  subject_kind?: string;
  subject?: string;
  content_hash?: string;
  prog_type?: number;
}

export interface Learned {
  key: LearnedKey;
  exe_path?: string;
  occurrences: number;
  first_seen: string;
  last_seen: string;
  hosts: string[];
  /** The stored first-sighting event: the evidence for a new hook. */
  first_event_id?: string;
}

export interface AllowlistEntry {
  id: string;
  created_at: string;
  created_by: string;
  description: string;
  event_types: EventType[] | null;
  exe_hash: string;
  exe_path: string;
  library_hash: string;
  library_path: string;
  prog_name: string;
  prog_type?: number | null;
  prog_hash: string;
  host_pattern: string;
  uid_range?: UIDRange | null;
  container_image: string;
  allowed_rpaths?: string[];
  /** Scopes the entry to one enrolled host; empty is the whole fleet. */
  host_id?: string;
  action: PolicyAction;
  expires?: string | null;
  enabled: boolean;
  status?: EntryStatus;
  learned?: Learned;
}

/** One sensor's state from the host's latest heartbeat. */
export interface SensorHealth {
  name: string;
  /** alive, dead, failed, unverifiable or unknown */
  status: string;
  reason?: string;
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
  sensors?: SensorHealth[];
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

export interface LearningWindow {
  scope: 'fleet' | 'host';
  host_id?: string;
  started_at: string;
  ends_at: string;
  started_by?: string;
  active: boolean;
}

export interface LearningState {
  now: string;
  windows: LearningWindow[];
}

/** POST /api/v1/policies/decide: one decision for 1 to 1000 PENDING entries. */
export type BulkDecision = 'approve' | 'reject';

/**
 * fleet: each entry applies to every host. seen_hosts: one entry per host
 * the hook was seen on, and no other host.
 */
export type BulkScope = 'fleet' | 'seen_hosts';

export interface DecideResult {
  id: string;
  ok: boolean;
  /** The entries now in force for this hook (one per host for seen_hosts). */
  entries?: AllowlistEntry[];
  error?: string;
}

export interface DecideResponse {
  results: DecideResult[];
}

/** A decision on a PENDING entry, or the scope of an entry made from an event. */
export type Scope = { scope: 'fleet' } | { scope: 'host'; host_id: string };

export interface EnrollmentTokenStatus {
  name: string;
  expires: string;
  expired: boolean;
  single_use: boolean;
}

export interface ConnectorStatus {
  name: string;
  min_severity: string;
  sent: number;
  dropped: number;
  failed: number;
  queued: number;
}

/** GET /api/v1/settings. It holds no secrets. */
export interface ServerSettings {
  version: string;
  tls: boolean;
  grpc_addr: string;
  enroll_addr: string;
  http_addr: string;
  enrollment: {
    enabled: boolean;
    tokens: EnrollmentTokenStatus[];
  };
  connectors: ConnectorStatus[];
  websocket: {
    subscribers: number;
    published: number;
    lagged: number;
    buffer: number;
    protocol: string;
    token_protocol_prefix: string;
    allowed_origins: string[];
  };
}
