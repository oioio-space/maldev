package dllhijack

import "strings"

// Kind distinguishes the victim surface (service / running process /
// scheduled task). Only Service is populated in v0.12.2.
type Kind int

const (
	KindService Kind = iota + 1
	KindProcess
	KindScheduledTask
)

func (k Kind) String() string {
	switch k {
	case KindService:
		return "service"
	case KindProcess:
		return "process"
	case KindScheduledTask:
		return "scheduled-task"
	default:
		return "unknown"
	}
}

// Opportunity describes one discovered DLL hijack candidate. The caller
// should treat every field as reconnaissance data, not an assertion of
// exploitability — confirm by dropping a canary DLL + triggering the
// victim (see the canary/Validate helpers shipped alongside).
type Opportunity struct {
	Kind        Kind
	ID          string // ServiceName / PID / TaskPath depending on Kind
	DisplayName string // human-readable label, may be empty
	BinaryPath  string // the exe that loads DLLs at runtime

	// HijackedDLL is the import name that would be hijacked, e.g. "version.dll".
	HijackedDLL string
	// HijackedPath is the exact file path where a payload DLL can be
	// dropped so the victim loads it BEFORE reaching the legitimate copy.
	HijackedPath string
	// ResolvedDLL is the path the victim currently loads the DLL from
	// (typically System32). Empty if the scanner could not resolve it.
	ResolvedDLL string

	SearchDir string // directory where a dropped DLL would sit (= dirname(HijackedPath))
	Writable  bool   // true if the current user can write to SearchDir
	Reason    string // why this Opportunity was flagged
}

// ParseBinaryPath extracts the executable path from a service
// BinaryPathName as recorded in the Windows SCM. Handles quoted paths
// (`"C:\Program Files\...\svc.exe" -arg`) and unquoted paths
// (`C:\Windows\System32\svc.exe -k ArgName`). Returns "" on failure.
//
// Pure string parsing — exported for callers that read BinaryPathName
// from a non-SCM source (registry, event log, etc.) and for
// cross-platform unit tests.
func ParseBinaryPath(cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return ""
	}
	if cmdline[0] == '"' {
		end := strings.IndexByte(cmdline[1:], '"')
		if end < 0 {
			return ""
		}
		return cmdline[1 : 1+end]
	}
	if sp := strings.IndexAny(cmdline, " \t"); sp > 0 {
		return cmdline[:sp]
	}
	return cmdline
}
