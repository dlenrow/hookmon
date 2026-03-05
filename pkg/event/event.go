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

	// Filled by server after policy evaluation
	PolicyResult *PolicyResult `json:"policy_result,omitempty"`
}

// BPFDetail contains details specific to bpf() syscall events.
type BPFDetail struct {
	BPFCommand uint32 `json:"bpf_cmd"`
	ProgType   uint32 `json:"prog_type"`
	ProgName   string `json:"prog_name"`
	AttachType uint32 `json:"attach_type"`
	TargetFD   int32  `json:"target_fd"`
	InsnCount  uint32 `json:"insn_count"`
	ProgHash   string `json:"prog_hash"`
}

// ExecInjectionDetail contains details specific to exec injection events
// (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, LD_DEBUG).
type ExecInjectionDetail struct {
	LibraryPath  string `json:"library_path"`
	LibraryHash  string `json:"library_hash"`
	TargetBinary string `json:"target_binary"`
	SetBy        string `json:"set_by"`
	EnvVar       string `json:"env_var,omitempty"` // which env var triggered: LD_PRELOAD, LD_AUDIT, etc.
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

// AllowlistEntry defines a single allowlist rule.
type AllowlistEntry struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	Description string    `json:"description"`

	// Match criteria (AND logic for non-empty fields)
	EventTypes     []EventType `json:"event_types"`
	ExeHash        string      `json:"exe_hash"`
	ExePath        string      `json:"exe_path"`
	LibraryHash    string      `json:"library_hash"`
	LibraryPath    string      `json:"library_path"`
	ProgName       string      `json:"prog_name"`
	ProgType       *uint32     `json:"prog_type"`
	ProgHash       string      `json:"prog_hash"`
	HostPattern    string      `json:"host_pattern"`
	UIDRange       *UIDRange   `json:"uid_range"`
	ContainerImage string      `json:"container_image"`
	AllowedRpaths  []string    `json:"allowed_rpaths,omitempty"`

	Action  PolicyAction `json:"action"`
	Expires *time.Time   `json:"expires"`
	Enabled bool         `json:"enabled"`
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
}
