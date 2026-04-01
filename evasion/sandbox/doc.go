// Package sandbox provides a configurable sandbox/VM evasion orchestrator
// that aggregates multiple detection checks into a single assessment.
//
// Technique: Multi-factor sandbox and analysis environment detection.
// MITRE ATT&CK: T1497 (Virtualization/Sandbox Evasion)
// Platform: Cross-platform (Windows and Linux)
// Detection: Low -- individual checks are benign; combined behavior may be flagged.
//
// The Checker aggregates the following checks:
//   - Debugger detection (via antidebug package)
//   - Virtual machine detection (via antivm package)
//   - CPU core count, RAM, and disk space thresholds
//   - Suspicious usernames and hostnames
//   - Analysis tool process names
//   - Fake domain DNS interception (sandbox network simulation)
//   - Time-based evasion via CPU-burning waits
//
// Example:
//
//	checker := sandbox.NewCheckerDefault()
//	if sandboxed, reason, _ := checker.IsSandboxed(); sandboxed {
//	    os.Exit(0) // bail out of sandbox
//	}
package sandbox
