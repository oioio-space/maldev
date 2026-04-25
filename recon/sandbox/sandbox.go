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
