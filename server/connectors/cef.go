package connectors

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dlenrow/hookmon/pkg/event"
)

// CEF (ArcSight Common Event Format) for the syslog connector.
//
// Header: CEF:0|HookMon|HookMon|1.0|<event type>|<name>|<severity 0-10>|
//
// Extension fields on every event:
//
//	rt                 detection time, milliseconds since the epoch
//	externalId         event ID
//	deviceExternalId   host ID (the bus certificate's CN)
//	shost              monitored host's hostname
//	cs3 ExeHash        acting binary's sha256 (when known)
//	cs4 PolicyResult   ALLOW, ALERT or DENY
//	reason             why the policy decided as it did
//
// Process context, on events that have a process (PID or executable):
//
//	suid, spid, sproc (executable path), flexString1 Cmdline,
//	flexString2 ContainerID
//
// By event type (cs1-cs6 and cn1-cn3 are reused, each with its Label):
//
//	BPF_LOAD, BPF_ATTACH  cs1 ProgType, cs2 ProgName, cs5 ProgTag,
//	                      cs6 AttachTarget, cn1 InsnCount, cn2 ProgID,
//	                      cn3 BPFCommand
//	BPF_INVENTORY         cs1 ProgType, cs2 ProgName, cs5 ProgTag,
//	                      cs6 ScanID, cn2 ProgID, cn3 ProgCount (summary)
//	EXEC_INJECTION        cs1 LibraryPath, cs2 SetBy, cs5 EnvVar,
//	                      cs6 TargetBinary, fileHash (library),
//	                      cn1 ScanTruncated, cn2 ValueTruncated
//	SHM_CREATE            cs1 SHMName, cs2 Pattern, fsize
//	DLOPEN                cs1 LibraryPath, fileHash (library), cn1 Flags
//	LINKER_CONFIG         cs1 FilePath, cs2 Operation, oldFileHash, fileHash
//	LIB_INTEGRITY         cs1 LibraryPath, cs2 Operation, oldFileHash,
//	                      fileHash, cn1 InLdCache (0 or 1)
//	PTRACE_INJECT         cs1 Request (name), cs2 TargetComm, cs5 Addr (hex),
//	                      dpid, dproc (target), cn1 RequestNum
//	ELF_RPATH             cs1 RpathRaw, cs2 RunpathRaw, cs5 HighestRisk,
//	                      cn1 Setuid (0 or 1)
//	AGENT_OFFLINE         the common fields only
//
// Values are escaped as CEF requires: in the header, backslash and pipe;
// in extensions, backslash and equals sign, with CR and LF written as \r
// and \n, so a message is always one line.

// cefVersion is the Device Version in the CEF header.
const cefVersion = "1.0"

// severityToNum maps HookMon severity to CEF severity (0-10).
func severityToNum(sev event.Severity) int {
	switch sev {
	case event.SeverityInfo:
		return 1
	case event.SeverityWarn:
		return 4
	case event.SeverityAlert:
		return 7
	case event.SeverityCritical:
		return 10
	default:
		return 0
	}
}

// eventDescription is the CEF Name for an event type.
func eventDescription(et event.EventType) string {
	switch et {
	case event.EventBPFLoad:
		return "BPF Program Loaded"
	case event.EventBPFAttach:
		return "BPF Program Attached"
	case event.EventExecInjection:
		return "Exec Injection Detected"
	case event.EventSHMCreate:
		return "Suspicious Shared Memory Created"
	case event.EventDlopen:
		return "Dynamic Library Loaded via dlopen"
	case event.EventLinkerConfig:
		return "Linker Configuration Modified"
	case event.EventPtraceInject:
		return "Ptrace Code Injection Detected"
	case event.EventLibIntegrity:
		return "Shared Library Modified on Disk"
	case event.EventElfRpath:
		return "Suspicious ELF RPATH/RUNPATH Detected"
	case event.EventBPFInventory:
		return "BPF Program Inventory"
	case event.EventAgentOffline:
		return "Sensor Bus Offline"
	case event.EventAgentRecovered:
		return "Sensor Bus Recovered"
	default:
		return "Unknown Hook Event"
	}
}

// cefExt builds a CEF extension.
type cefExt struct{ parts []string }

func (x *cefExt) add(key, value string) {
	x.parts = append(x.parts, key+"="+cefExtEscape(value))
}

func (x *cefExt) str(key, value string) {
	if value != "" {
		x.add(key, value)
	}
}

func (x *cefExt) num(key string, n int64) {
	x.parts = append(x.parts, key+"="+strconv.FormatInt(n, 10))
}

// cs adds custom string n (1-6) with its label, if value is set.
func (x *cefExt) cs(n int, label, value string) {
	if value == "" {
		return
	}
	k := "cs" + strconv.Itoa(n)
	x.parts = append(x.parts, k+"Label="+label)
	x.add(k, value)
}

// cn adds custom number n (1-3) with its label.
func (x *cefExt) cn(n int, label string, v int64) {
	k := "cn" + strconv.Itoa(n)
	x.parts = append(x.parts, k+"Label="+label)
	x.num(k, v)
}

func (x *cefExt) flex(n int, label, value string) {
	if value == "" {
		return
	}
	// flexString values are at most 1023 characters.
	if len(value) > 1023 {
		value = value[:1023]
	}
	k := "flexString" + strconv.Itoa(n)
	x.parts = append(x.parts, k+"Label="+label)
	x.add(k, value)
}

func boolNum(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// formatCEF produces the CEF message for an event.
func formatCEF(evt *event.HookEvent) string {
	var x cefExt

	if !evt.Timestamp.IsZero() {
		x.num("rt", evt.Timestamp.UnixMilli())
	}
	x.str("externalId", evt.ID)
	x.str("deviceExternalId", evt.HostID)
	x.str("shost", evt.Hostname)

	if evt.PID != 0 || evt.ExePath != "" {
		x.num("suid", int64(evt.UID))
		if evt.PID != 0 {
			x.num("spid", int64(evt.PID))
		}
		x.str("sproc", evt.ExePath)
		x.flex(1, "Cmdline", evt.Cmdline)
		x.flex(2, "ContainerID", evt.ContainerID)
	}

	x.cs(3, "ExeHash", evt.ExeHash)
	if pr := evt.PolicyResult; pr != nil {
		x.cs(4, "PolicyResult", string(pr.Action))
		x.str("reason", pr.Reason)
	}

	switch {
	case evt.BPFInventoryDetail != nil:
		if d := evt.BPFDetail; d != nil {
			x.cs(1, "ProgType", strconv.FormatUint(uint64(d.ProgType), 10))
			x.cs(2, "ProgName", d.ProgName)
			x.cs(5, "ProgTag", d.ProgHash)
			if d.ProgID != 0 {
				x.cn(2, "ProgID", int64(d.ProgID))
			}
		}
		inv := evt.BPFInventoryDetail
		x.cs(6, "ScanID", inv.ScanID)
		if inv.Summary {
			x.cn(3, "ProgCount", int64(inv.ProgCount))
		}

	case evt.BPFDetail != nil:
		d := evt.BPFDetail
		x.cs(1, "ProgType", strconv.FormatUint(uint64(d.ProgType), 10))
		x.cs(2, "ProgName", d.ProgName)
		x.cs(5, "ProgTag", d.ProgHash)
		x.cs(6, "AttachTarget", d.AttachTarget)
		if d.InsnCount > 0 {
			x.cn(1, "InsnCount", int64(d.InsnCount))
		}
		if d.ProgID != 0 {
			x.cn(2, "ProgID", int64(d.ProgID))
		}
		x.cn(3, "BPFCommand", int64(d.BPFCommand))

	case evt.ExecInjectionDetail != nil:
		d := evt.ExecInjectionDetail
		x.cs(1, "LibraryPath", d.LibraryPath)
		x.cs(2, "SetBy", d.SetBy)
		x.cs(5, "EnvVar", d.EnvVar)
		x.cs(6, "TargetBinary", d.TargetBinary)
		x.str("fileHash", d.LibraryHash)
		if d.ScanTruncated {
			x.cn(1, "ScanTruncated", 1)
		}
		if d.ValueTruncated {
			x.cn(2, "ValueTruncated", 1)
		}

	case evt.SHMDetail != nil:
		d := evt.SHMDetail
		x.cs(1, "SHMName", d.SHMName)
		x.cs(2, "Pattern", d.Pattern)
		if d.Size > 0 {
			x.num("fsize", int64(d.Size))
		}

	case evt.DlopenDetail != nil:
		d := evt.DlopenDetail
		x.cs(1, "LibraryPath", d.LibraryPath)
		x.str("fileHash", d.LibraryHash)
		x.cn(1, "Flags", int64(d.Flags))

	case evt.LinkerConfigDetail != nil:
		d := evt.LinkerConfigDetail
		x.cs(1, "FilePath", d.FilePath)
		x.cs(2, "Operation", d.Operation)
		x.str("oldFileHash", d.OldHash)
		x.str("fileHash", d.NewHash)

	case evt.LibIntegrityDetail != nil:
		d := evt.LibIntegrityDetail
		x.cs(1, "LibraryPath", d.LibraryPath)
		x.cs(2, "Operation", d.Operation)
		x.str("oldFileHash", d.OldHash)
		x.str("fileHash", d.NewHash)
		x.cn(1, "InLdCache", boolNum(d.InLdCache))

	case evt.PtraceDetail != nil:
		d := evt.PtraceDetail
		x.cs(1, "Request", d.RequestName)
		x.cs(2, "TargetComm", d.TargetComm)
		if d.Addr != 0 {
			x.cs(5, "Addr", fmt.Sprintf("0x%x", d.Addr))
		}
		if d.TargetPID != 0 {
			x.num("dpid", int64(d.TargetPID))
		}
		x.str("dproc", d.TargetComm)
		x.cn(1, "RequestNum", int64(d.Request))

	case evt.ElfRpathDetail != nil:
		d := evt.ElfRpathDetail
		x.cs(1, "RpathRaw", d.RpathRaw)
		x.cs(2, "RunpathRaw", d.RunpathRaw)
		x.cs(5, "HighestRisk", string(d.HighestRisk))
		x.cn(1, "Setuid", boolNum(d.IsSetuid))
	}

	return fmt.Sprintf("CEF:0|HookMon|HookMon|%s|%s|%s|%d|%s",
		cefVersion,
		cefHeaderEscape(string(evt.EventType)),
		cefHeaderEscape(eventDescription(evt.EventType)),
		severityToNum(evt.Severity),
		strings.Join(x.parts, " "),
	)
}

// cefHeaderEscape escapes a CEF header field: backslash and pipe. CR and
// LF become \r and \n so the message stays on one line.
func cefHeaderEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\r", `\r`, "\n", `\n`).Replace(s)
}

// cefExtEscape escapes a CEF extension value: backslash and equals sign,
// with CR and LF written as \r and \n. Pipes need no escaping in
// extensions.
func cefExtEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r", `\r`, "\n", `\n`).Replace(s)
}
