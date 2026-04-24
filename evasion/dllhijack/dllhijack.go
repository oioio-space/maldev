package dllhijack

import (
	"bytes"
	"sort"
	"strings"
)

// Kind distinguishes the victim surface (service / running process /
// scheduled task). Only Service is populated in v0.12.2.
type Kind int

const (
	KindService Kind = iota + 1
	KindProcess
	KindScheduledTask
	// KindAutoElevate: auto-elevating binary discovered under System32
	// whose application manifest sets autoElevate=true. Hijacking the
	// DLL search order around such a binary yields a UAC bypass
	// (MITRE T1548.002).
	KindAutoElevate
)

func (k Kind) String() string {
	switch k {
	case KindService:
		return "service"
	case KindProcess:
		return "process"
	case KindScheduledTask:
		return "scheduled-task"
	case KindAutoElevate:
		return "auto-elevate"
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

	// AutoElevate is true when the victim binary's embedded manifest
	// sets autoElevate=true — it silently elevates to High integrity on
	// launch (UAC bypass vector, MITRE T1548.002).
	AutoElevate bool
	// IntegrityGain is true when a successful hijack would run our
	// payload at a higher integrity level than the current process.
	// Implies AutoElevate for process-launch flows, or SYSTEM for
	// service-based flows, or any other elevation pathway.
	IntegrityGain bool
	// Score is a coarse ranking hint (higher = more impactful).
	// Computed by Rank; 0 until Rank is called.
	Score int
}

// Rank assigns a coarse Score to each Opportunity in-place and returns
// a new slice sorted by descending Score. The scoring rewards
// integrity-gain flows (auto-elevate, SYSTEM services) over
// same-level drops (process hijack of the current user's own apps).
//
// Weights (tune freely):
//
//	+200 AutoElevate (UAC bypass vector)
//	+100 IntegrityGain (separate from AutoElevate: SYSTEM service, etc.)
//	+ 50 KindService (runs as SYSTEM or LOCAL SERVICE typically)
//	+ 20 KindScheduledTask (stealthy persistence, trigger flexibility)
//	+ 10 KindAutoElevate base (on top of AutoElevate)
//	+  5 KindProcess (noisy, risky)
//	+ 15 non-KnownDLL with single-character filename difference to a
//	     KnownDLL (operator confusion risk — deprioritize) — actually
//	     omitted to keep the scoring deterministic and simple
//
// Ties are broken alphabetically by BinaryPath + HijackedDLL for
// stable output.
func Rank(opps []Opportunity) []Opportunity {
	scored := make([]Opportunity, len(opps))
	copy(scored, opps)
	for i := range scored {
		s := 0
		if scored[i].AutoElevate {
			s += 200
		}
		if scored[i].IntegrityGain {
			s += 100
		}
		switch scored[i].Kind {
		case KindService:
			s += 50
		case KindScheduledTask:
			s += 20
		case KindAutoElevate:
			s += 10
		case KindProcess:
			s += 5
		}
		scored[i].Score = s
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].Score != scored[j].Score {
			return scored[i].Score > scored[j].Score
		}
		if scored[i].BinaryPath != scored[j].BinaryPath {
			return scored[i].BinaryPath < scored[j].BinaryPath
		}
		return scored[i].HijackedDLL < scored[j].HijackedDLL
	})
	return scored
}

// IsAutoElevate returns true when the given PE bytes embed an
// application manifest with <autoElevate>true</autoElevate> or the
// attribute-style autoElevate="true". Cheap byte-level match — no XML
// parsing — because the manifest is stored verbatim in the RT_MANIFEST
// resource and the substring is distinctive enough.
//
// Pure cross-platform so callers can audit PE bytes from any host.
func IsAutoElevate(peBytes []byte) bool {
	lower := bytes.ToLower(peBytes)
	needle := []byte("autoelevate")
	for idx := 0; ; {
		i := bytes.Index(lower[idx:], needle)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + 64
		if end > len(lower) {
			end = len(lower)
		}
		window := lower[start:end]
		if bytes.Contains(window, []byte(">true<")) || bytes.Contains(window, []byte(`="true"`)) {
			return true
		}
		idx = start + len(needle)
	}
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
