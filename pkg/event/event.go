package event

import "time"

// EventType identifies the kind of hook event detected.
type EventType string

const (
	EventBPFLoad       EventType = "BPF_LOAD"
	EventBPFAttach     EventType = "BPF_ATTACH"
	EventLDPreload     EventType = "LD_PRELOAD"
	EventSHMCreate     EventType = "SHM_CREATE"
	EventDlopen        EventType = "DLOPEN"
	EventAgentOffline  EventType = "AGENT_OFFLINE"
	EventAgentRecovered EventType = "AGENT_RECOVERED"
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
	PreloadDetail *PreloadDetail `json:"preload_detail,omitempty"`
	SHMDetail     *SHMDetail     `json:"shm_detail,omitempty"`
	DlopenDetail  *DlopenDetail  `json:"dlopen_detail,omitempty"`

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

// PreloadDetail contains details specific to LD_PRELOAD events.
type PreloadDetail struct {
	LibraryPath  string `json:"library_path"`
	LibraryHash  string `json:"library_hash"`
	TargetBinary string `json:"target_binary"`
	SetBy        string `json:"set_by"`
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
	HostPattern    string      `json:"host_pattern"`
	UIDRange       *UIDRange   `json:"uid_range"`
	ContainerImage string      `json:"container_image"`

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
