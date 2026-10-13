package event

import "time"

// EventType identifies the kind of hook event detected.
type EventType string

const (
	EventBPFLoad       EventType = "BPF_LOAD"
	EventBPFAttach     EventType = "BPF_ATTACH"
	EventExecInjection EventType = "EXEC_INJECTION"
	EventSHMCreate     EventType = "SHM_CREATE"
	EventDlopen        EventType = "DLOPEN"
	EventLinkerConfig  EventType = "LINKER_CONFIG"
	EventPtraceInject  EventType = "PTRACE_INJECT"
	EventLibIntegrity  EventType = "LIB_INTEGRITY"
	EventAgentOffline  EventType = "AGENT_OFFLINE"
	EventAgentRecovered EventType = "AGENT_RECOVERED"
	EventElfRpath       EventType = "ELF_RPATH"
	EventBPFInventory   EventType = "BPF_INVENTORY"
)

// Severity levels for events.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarn     Severity = "WARN"
	SeverityAlert    Severity = "ALERT"
	SeverityCritical Severity = "CRITICAL"
)

// HookEvent is the canonical event produced by sensors and processed by the server.
type HookEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	HostID    string    `json:"host_id"`
	Hostname  string    `json:"hostname"`

	EventType EventType `json:"event_type"`
	Severity  Severity  `json:"severity"`

	// Process context
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Comm        string `json:"comm"`
	Cmdline     string `json:"cmdline"`
	ExePath     string `json:"exe_path"`
	ExeHash     string `json:"exe_hash"`
	CgroupPath  string `json:"cgroup_path"`
	ContainerID string `json:"container_id"`
	Namespace   string `json:"namespace"`

	// Event-type-specific payloads
	BPFDetail     *BPFDetail     `json:"bpf_detail,omitempty"`
	ExecInjectionDetail *ExecInjectionDetail `json:"exec_injection_detail,omitempty"`
	SHMDetail     *SHMDetail     `json:"shm_detail,omitempty"`
	DlopenDetail        *DlopenDetail        `json:"dlopen_detail,omitempty"`
	LinkerConfigDetail  *LinkerConfigDetail  `json:"linker_config_detail,omitempty"`
	PtraceDetail        *PtraceDetail        `json:"ptrace_detail,omitempty"`
	LibIntegrityDetail  *LibIntegrityDetail  `json:"lib_integrity_detail,omitempty"`
	ElfRpathDetail      *ElfRpathDetail      `json:"elf_rpath_detail,omitempty"`
	BPFInventoryDetail  *BPFInventoryDetail  `json:"bpf_inventory_detail,omitempty"`

	// Filled by server after policy evaluation
	PolicyResult *PolicyResult `json:"policy_result,omitempty"`
}

// BPFDetail contains details specific to bpf() syscall events and to
// per-program BPF_INVENTORY events.
//
// For BPF_LOAD it describes the program the call created; for BPF_ATTACH,
// the program being attached. ProgID, ProgHash, LoadTime and CreatedByUID
// are the kernel's view of that program. They are empty when a load failed
// or the program could not be read.
type BPFDetail struct {
	BPFCommand uint32 `json:"bpf_cmd"`
	ProgType   uint32 `json:"prog_type"`
	ProgName   string `json:"prog_name"`
	AttachType uint32 `json:"attach_type"`
	TargetFD   int32  `json:"target_fd"`
	InsnCount  uint32 `json:"insn_count"`

	// ProgHash is the kernel's program tag in hex, as `bpftool prog show`
	// prints it: the first 8 bytes of a SHA-1 over the instructions, with
	// the map references in ld_imm64 instructions zeroed. It is the same for
	// every load of the same bytecode on the same kernel, whatever map fds
	// the loader used, and it changes when any instruction changes.
	ProgHash string `json:"prog_hash"`

	ProgID       uint32     `json:"prog_id,omitempty"`
	LoadTime     *time.Time `json:"load_time,omitempty"`
	CreatedByUID *uint32    `json:"created_by_uid,omitempty"`

	// AttachTarget is the tracepoint name of a BPF_RAW_TRACEPOINT_OPEN.
	AttachTarget string `json:"attach_target,omitempty"`
}

// BPFInventoryDetail describes a BPF_INVENTORY event. Each inventory scan
// emits one event per loaded BPF program (Summary false, and BPFDetail
// describes the program), then one host summary (Summary true). All events
// of one scan carry the same ScanID.
type BPFInventoryDetail struct {
	ScanID  string `json:"scan_id"`
	Summary bool   `json:"summary"`

	// Summary only: how many programs the scan reported, in total and by
	// program type name.
	ProgCount uint32            `json:"prog_count,omitempty"`
	ByType    map[string]uint32 `json:"by_type,omitempty"`
}

// ExecInjectionDetail contains details specific to exec injection events
// (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, LD_DEBUG).
type ExecInjectionDetail struct {
	LibraryPath  string `json:"library_path"`
	LibraryHash  string `json:"library_hash"`
	TargetBinary string `json:"target_binary"`
	SetBy        string `json:"set_by"`
	EnvVar       string `json:"env_var,omitempty"` // which env var triggered: LD_PRELOAD, LD_AUDIT, etc.

	// ScanTruncated marks an event that names no variable: the sensor
	// stopped before the end of the process's environment (more variables
	// than it scans, a read that failed, or too many matches), so an LD_*
	// variable may be in the part it did not scan. It is a separate event;
	// variables found before the scan stopped have their own events.
	ScanTruncated bool `json:"scan_truncated,omitempty"`

	// ValueTruncated is set when the variable's value was longer than the
	// sensor captures. LibraryPath then holds only its start, and
	// LibraryHash is empty.
	ValueTruncated bool `json:"value_truncated,omitempty"`
}

// SHMDetail contains details specific to shared memory events.
type SHMDetail struct {
	SHMName string `json:"shm_name"`
	Size    uint64 `json:"size"`
	Pattern string `json:"pattern"`
}

// DlopenDetail contains details specific to dlopen() events.
type DlopenDetail struct {
	LibraryPath string `json:"library_path"`
	LibraryHash string `json:"library_hash"`
	Flags       int    `json:"flags"`
}

// LinkerConfigDetail contains details specific to linker config file modification events.
type LinkerConfigDetail struct {
	FilePath  string `json:"file_path"`
	Operation string `json:"operation"` // "write", "create", "delete", "rename"
	OldHash   string `json:"old_hash,omitempty"`
	NewHash   string `json:"new_hash,omitempty"`
}

// PtraceDetail contains details specific to ptrace injection events.
type PtraceDetail struct {
	Request     uint32 `json:"request"`
	RequestName string `json:"request_name"`
	TargetPID   uint32 `json:"target_pid"`
	TargetComm  string `json:"target_comm"`
	Addr        uint64 `json:"addr,omitempty"`
}

// LibIntegrityDetail contains details specific to shared library modification events.
type LibIntegrityDetail struct {
	LibraryPath string `json:"library_path"`
	Operation   string `json:"operation"` // "write", "rename", "delete"
	OldHash     string `json:"old_hash,omitempty"`
	NewHash     string `json:"new_hash,omitempty"`
	InLdCache   bool   `json:"in_ld_cache"`
}

// RpathRisk classifies the risk level of an RPATH/RUNPATH entry.
type RpathRisk string

const (
	RpathRiskNone     RpathRisk = "NONE"
	RpathRiskLow      RpathRisk = "LOW"
	RpathRiskMedium   RpathRisk = "MEDIUM"
	RpathRiskHigh     RpathRisk = "HIGH"
	RpathRiskCritical RpathRisk = "CRITICAL"
)

// RpathEntry describes a single path from DT_RPATH or DT_RUNPATH with its risk classification.
type RpathEntry struct {
	Path    string    `json:"path"`
	Risk    RpathRisk `json:"risk"`
	Reason  string    `json:"reason"`
	Exists  bool      `json:"exists"`
	IsRpath bool      `json:"is_rpath"` // true = DT_RPATH (deprecated), false = DT_RUNPATH
}

// ElfRpathDetail contains details specific to ELF RPATH/RUNPATH analysis events.
type ElfRpathDetail struct {
	HasRpath      bool         `json:"has_rpath"`
	HasRunpath    bool         `json:"has_runpath"`
	RpathRaw      string       `json:"rpath_raw,omitempty"`
	RunpathRaw    string       `json:"runpath_raw,omitempty"`
	Entries       []RpathEntry `json:"entries"`
	HighestRisk   RpathRisk    `json:"highest_risk"`
	UsesOrigin    bool         `json:"uses_origin"`
	UsesDeprecated bool        `json:"uses_deprecated"` // true if DT_RPATH is present
	IsSetuid      bool         `json:"is_setuid"`
}

// PolicyAction defines what the server does when an event matches a policy.
type PolicyAction string

const (
	ActionAllow PolicyAction = "ALLOW"
	ActionAlert PolicyAction = "ALERT"
	ActionDeny  PolicyAction = "DENY"
)

// PolicyResult is the outcome of evaluating an event against the allowlist.
type PolicyResult struct {
	Action         PolicyAction `json:"action"`
	MatchedEntryID string       `json:"matched_entry_id,omitempty"`
	Reason         string       `json:"reason"`
	// Disposition is what the server does with the event: see Disposition.
	Disposition Disposition `json:"disposition,omitempty"`
	// CandidateID is the PENDING entry for the event's key, on a first
	// sighting or a repeat.
	CandidateID string `json:"candidate_id,omitempty"`
	// Quiet marks a first sighting during a learning window: it is stored
	// and shown, but not sent to alert connectors.
	Quiet bool `json:"quiet,omitempty"`
}

// Disposition is what the server does with a hook event once the policy
// engine has evaluated it. A hook HookMon has not seen before is stored
// once, as a first sighting, and waits for a decision as a PENDING entry.
// Its repeats only add to that entry's count, and once it is allowed it is
// dropped. A denied hook is stored and alerts every time.
type Disposition string

const (
	// DispositionFirstSighting: no decided entry matched, and this event
	// created the PENDING entry for its key. Stored, shown and sent to the
	// connectors.
	DispositionFirstSighting Disposition = "first_sighting"
	// DispositionRepeat: no decided entry matched, and a PENDING entry for
	// the key already existed; its count, last seen time and hosts were
	// updated. Not stored, shown or sent.
	DispositionRepeat Disposition = "repeat"
	// DispositionAllowed: matched an entry with action ALLOW (or is a BPF
	// inventory summary). Not stored, shown or sent.
	DispositionAllowed Disposition = "allowed"
	// DispositionDenied: matched an ALERT or DENY entry, such as a rejected
	// candidate. Stored, shown and sent every time.
	DispositionDenied Disposition = "denied"
	// DispositionLifecycle: AGENT_OFFLINE or AGENT_RECOVERED.
	DispositionLifecycle Disposition = "lifecycle"
)

// Kept reports whether the server stores an event with this disposition,
// shows it on the live feed and sends it to the connectors. An event the
// policy engine did not evaluate (empty disposition) is kept.
func (d Disposition) Kept() bool {
	return d != DispositionRepeat && d != DispositionAllowed
}

// CandidateSighting is what recording an unmatched event's key found.
type CandidateSighting struct {
	// ID is the PENDING entry for the key, or "" when a decided entry for
	// the key is already in force (the policy engine had not loaded it yet).
	ID string
	// Created is true when this event created the PENDING entry: the key's
	// first sighting.
	Created bool
	// DecidedAction is the action of the decided entry in force when ID is
	// "": the most restrictive one when there are several.
	DecidedAction PolicyAction
}

// UIDRange defines a range of allowed UIDs.
type UIDRange struct {
	Min uint32 `json:"min"`
	Max uint32 `json:"max"`
}

// EntryStatus is an allowlist entry's review state.
type EntryStatus string

const (
	// StatusApproved entries are in force. Entries created through the API
	// are approved when created, and an empty status means approved.
	StatusApproved EntryStatus = "APPROVED"
	// StatusPending entries are new hooks waiting for a decision: the server
	// creates one the first time it sees an unmatched key. They never match
	// an event.
	StatusPending EntryStatus = "PENDING"
	// StatusRejected entries are new hooks an operator denied. They match
	// with action ALERT, so the hook alerts every time it happens again and
	// is never proposed again.
	StatusRejected EntryStatus = "REJECTED"
)

// AllowlistEntry defines a single allowlist rule.
type AllowlistEntry struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	Description string    `json:"description"`

	// Match criteria (AND logic for non-empty fields)
	EventTypes  []EventType `json:"event_types"`
	ExeHash     string      `json:"exe_hash"`
	ExePath     string      `json:"exe_path"`
	LibraryHash string      `json:"library_hash"`
	LibraryPath string      `json:"library_path"`
	ProgName    string      `json:"prog_name"`
	ProgType    *uint32     `json:"prog_type"`
	// ProgHash is the kernel program tag (16 hex digits, as BPFDetail.ProgHash
	// holds it). Identical instructions share a tag across program types, so
	// pin ProgType alongside it.
	ProgHash       string    `json:"prog_hash"`
	HostPattern    string    `json:"host_pattern"`
	UIDRange       *UIDRange `json:"uid_range"`
	ContainerImage string    `json:"container_image"`
	AllowedRpaths  []string  `json:"allowed_rpaths,omitempty"`

	// HostID limits the entry to one enrolled host (the host ID from its
	// certificate). Empty means the whole fleet.
	HostID string `json:"host_id,omitempty"`

	Action  PolicyAction `json:"action"`
	Expires *time.Time   `json:"expires"`
	Enabled bool         `json:"enabled"`

	// Status is the review state. Only APPROVED (or empty) and REJECTED
	// entries match events.
	Status EntryStatus `json:"status,omitempty"`

	// Learned is set on entries the server created for a new hook. Such an entry matches
	// exactly the events whose key equals Learned.Key, as well as any match
	// criteria above.
	Learned *Learned `json:"learned,omitempty"`
}

// LearnedKey is the dedupe key of a new hook: the tuple a PENDING entry
// stands for. Every unmatched event with the same key counts toward the
// same entry, and approving the entry allows exactly those events.
//
// The key identifies WHAT was loaded or changed, not who loaded it:
// the acting binary, the host, the user and the container are context
// on the event, not part of the key. BPF load, attach and inventory
// events share one key when they name the same program.
type LearnedKey struct {
	// SubjectKind names the mechanism and what Subject holds:
	//   "bpf_tag", "bpf_name"           — BPF program (all BPF event types)
	//   "ld_preload", "ld_audit"         — library injection via env var
	//   "ld_library_path", "ld_debug"    — path/debug injection via env var
	//   "scan_truncated"                 — incomplete environment scan
	//   "dlopen"                         — runtime dlopen() call
	//   "lib_replace"                    — shared library file replaced on disk
	//   "linker_config"                  — ld.so config file changed
	//   "shm_pattern", "shm_name"        — shared memory segment
	//   "rpath"                          — binary with risky RPATH (Subject = exe hash)
	//   "ptrace"                         — ptrace injection (Subject = tracer exe hash)
	SubjectKind string `json:"subject_kind,omitempty"`
	Subject     string `json:"subject,omitempty"`
	// ContentHash is the new content's "sha256:<hex>" for lib_replace and
	// linker_config events, so that each distinct replacement is its own key.
	ContentHash string `json:"content_hash,omitempty"`
	// ProgType is the BPF program type, part of the key for BPF events
	// because identical instructions of different types share a tag.
	ProgType uint32 `json:"prog_type,omitempty"`
}

// Learned is what the server recorded about a new hook for its allowlist entry.
type Learned struct {
	Key LearnedKey `json:"key"`
	// ExePath is the acting binary's path in the first event seen.
	ExePath     string    `json:"exe_path,omitempty"`
	Occurrences int64     `json:"occurrences"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	// Hosts are the IDs of the hosts the key was seen on. On an entry
	// approved or rejected for one host, it is that host.
	Hosts []string `json:"hosts"`
	// FirstEventID is the stored first-sighting event that created the
	// entry, the evidence to look at before deciding.
	FirstEventID string `json:"first_event_id,omitempty"`
}

// LearningWindow is a quiet period, for the whole fleet (HostID empty) or
// for one host: first sightings inside it are stored and shown, but not
// sent to alert connectors. Use it when HookMon first meets a fleet.
type LearningWindow struct {
	HostID    string    `json:"host_id"`
	StartedAt time.Time `json:"started_at"`
	EndsAt    time.Time `json:"ends_at"`
	StartedBy string    `json:"started_by,omitempty"`
}

// ActiveAt reports whether the window is open at t.
func (w LearningWindow) ActiveAt(t time.Time) bool {
	return t.Before(w.EndsAt)
}

// HostStatus tracks the status of a monitored host.
type HostStatus string

const (
	HostOnline       HostStatus = "ONLINE"
	HostUnresponsive HostStatus = "UNRESPONSIVE"
	HostOffline      HostStatus = "OFFLINE"
)

// Host represents a monitored host in the inventory.
type Host struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	IPAddress     string     `json:"ip_address"`
	AgentVersion  string     `json:"agent_version"`
	OSInfo        string     `json:"os_info"`
	Status        HostStatus `json:"status"`
	EnrolledAt    time.Time  `json:"enrolled_at"`
	LastHeartbeat time.Time  `json:"last_heartbeat"`
	LastEventAt   *time.Time `json:"last_event_at,omitempty"`

	// Sensors is the sensor-registry snapshot from the host's latest
	// heartbeat.
	Sensors []SensorHealth `json:"sensors,omitempty"`
}

// SensorHealth is one sensor's state as the bus's sensor registry reports it.
type SensorHealth struct {
	Name   string `json:"name"`
	Status string `json:"status"` // alive, dead, failed, unverifiable or unknown
	Reason string `json:"reason,omitempty"`
}

// HostHeartbeat is a heartbeat as the server records it.
type HostHeartbeat struct {
	// HostID is the authenticated host: the CN of the bus's client
	// certificate.
	HostID string
	// ReceivedAt is the server's clock when the heartbeat arrived. The bus's
	// own timestamp is not used, so a host's clock cannot hold it online.
	ReceivedAt   time.Time
	AgentVersion string
	Sensors      []SensorHealth
}
