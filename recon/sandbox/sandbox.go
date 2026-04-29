// Package sandbox provides a configurable sandbox/VM evasion orchestrator.
package sandbox

import (
	"runtime"
	"time"
)

// Config configures sandbox detection thresholds and indicator lists.
type Config struct {
	MinDiskGB      float64       // minimum expected disk size in GB
	MinRAMGB       float64       // minimum expected RAM in GB
	MinCPUCores    int           // minimum expected CPU cores
	BadUsernames   []string      // analyst usernames to detect
	BadHostnames   []string      // sandbox hostnames to detect
	BadProcesses   []string      // analysis tool process names to detect
	FakeDomain      string        // domain that should NOT respond (sandbox check)
	DiskPath        string        // disk path to check (default: "C:\" on Windows, "/" on Linux)
	MinProcesses    int           // minimum expected process count (default: 15)
	ConnectivityURL string        // URL to test real internet (default: "https://www.google.com")
	RequestTimeout  time.Duration // timeout for HTTP requests
	EvasionTimeout time.Duration // max time for evasion checks
	StopOnFirst    bool          // if true, IsSandboxed stops at first detection
}

// Result represents the outcome of a single sandbox detection check.
type Result struct {
	Name     string // "debugger", "vm", "cpu", "ram", "disk", "username", "hostname", "domain", "process"
	Detected bool
	Detail   string // e.g. "insufficient RAM: 2GB < 4GB minimum"
	Err      error  // non-nil only if the check itself failed
}

// detectionWeights assigns each check a 0..100-scale contribution
// to the aggregate sandbox score. Strong signals (active debugger,
// VM-detection probe, fake DNS reachable) carry the highest
// individual weight; cumulative weak signals can still push the
// score above the operator-chosen bail threshold.
//
// Sum of all weights = 116; the aggregate is capped at 100 so a
// "everything matched" outcome lands at the ceiling.
//
// Mirrors the Result.Name values produced by the platform-specific
// CheckAll implementations (debugger, vm, cpu, ram, disk, username,
// hostname, domain, process, process-count, connectivity).
var detectionWeights = map[string]int{
	"debugger":      20,
	"vm":            18,
	"domain":        15, // fake-domain-reachable = strong signal
	"process":       13, // analysis tool present in process list
	"username":      12,
	"hostname":      12,
	"process-count": 7,  // unusually low process count
	"connectivity":  6,  // no real internet egress
	"ram":           5,
	"disk":          5,
	"cpu":           3,
}

// Score aggregates a []Result (typically returned by
// (*Checker).CheckAll) into a single 0..100 confidence value.
// Each detected check contributes its mapped weight; the total is
// capped at 100. Undetected checks contribute zero.
//
// Unknown Result.Name values contribute zero — preserves forward-
// compatibility when CheckAll grows new check kinds before the
// weight table is updated. Callers that want strict accounting
// should snapshot the keys of Weights and iterate explicitly.
func Score(results []Result) int {
	total := 0
	for _, r := range results {
		if r.Detected {
			total += detectionWeights[r.Name]
		}
	}
	if total > 100 {
		return 100
	}
	return total
}

// Weights returns a copy of the per-check score weights so callers
// can audit / tune the algorithm without reaching into private
// state. Mutating the returned map is safe; the package's internal
// table is unchanged.
func Weights() map[string]int {
	out := make(map[string]int, len(detectionWeights))
	for k, v := range detectionWeights {
		out[k] = v
	}
	return out
}

// DefaultConfig returns sensible defaults for sandbox detection.
func DefaultConfig() Config {
	diskPath := "/"
	if runtime.GOOS == "windows" {
		diskPath = `C:\`
	}
	return Config{
		MinDiskGB:   64,
		MinRAMGB:    4,
		MinCPUCores: 2,
		BadUsernames: []string{
			"sandbox", "malware", "virus", "test", "analysis",
			"maltest", "currentuser", "user", "analyst",
		},
		BadHostnames: []string{
			"sandbox", "malware", "virus", "cuckoo", "anubis",
			"joe", "triage", "any.run",
		},
		BadProcesses: []string{
			"wireshark", "procmon", "procexp", "x64dbg", "x32dbg",
			"ollydbg", "ida", "ida64", "idaq", "idaq64",
			"fiddler", "httpdebugger", "burpsuite", "processhacker",
			"tcpview", "autoruns", "pestudio", "dnspy", "ghidra",
		},
		DiskPath:        diskPath,
		MinProcesses:    15,
		ConnectivityURL: "https://www.google.com",
		RequestTimeout:  5 * time.Second,
		StopOnFirst:     true,
	}
}
