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
	// StatusPending entries are learning-mode candidates waiting for review.
	// They never match an event.
	StatusPending EntryStatus = "PENDING"
	// StatusRejected entries are candidates an operator rejected. They match
	// with action ALERT, so the event keeps alerting and learning mode does
	// not propose it again.
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

	// Learned is set on entries learning mode created. Such an entry matches
	// exactly the events whose key equals Learned.Key, as well as any match
	// criteria above.
	Learned *Learned `json:"learned,omitempty"`
}

// LearnedKey is the learning-mode dedupe key: the tuple a PENDING entry
// stands for. Every unmatched event with the same key counts toward the
// same entry, and approving the entry allows exactly those events.
type LearnedKey struct {
	EventType EventType `json:"event_type"`
	// ExeHash is the acting binary's "sha256:<hex>", or "" when the bus could
	// not hash it (BPF_INVENTORY events have no process).
	ExeHash string `json:"exe_hash"`
	// SubjectKind names what Subject holds: "bpf_tag", "bpf_name" (only when
	// the kernel gave no tag), "library_hash", "library_path", "shm_pattern"
	// ("shm_name" only when the bus gave no pattern), "file_path", or "" for
	// event types with no subject (PTRACE_INJECT and ELF_RPATH, where the
	// exe hash identifies the binary).
	SubjectKind string `json:"subject_kind,omitempty"`
	Subject     string `json:"subject,omitempty"`
	// ProgType is the BPF program type, part of the key for BPF events
	// because identical instructions of different types share a tag.
	ProgType uint32 `json:"prog_type,omitempty"`
	// InContainer stands in for the container image, which the bus does not
	// report: true when the process ran in a container (the event had a
	// container ID). The exe hash, taken inside the container, identifies
	// the binary itself.
	InContainer bool `json:"in_container"`
}

// Learned is what learning mode recorded for an allowlist entry.
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
}

// LearningWindow is a period during which unmatched events become PENDING
// allowlist entries, for the whole fleet (HostID empty) or for one host.
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
