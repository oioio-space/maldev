// Package bsod triggers a Blue Screen of Death via NtRaiseHardError as a
// last-resort cleanup primitive.
//
// The package enables `SeShutdownPrivilege` via `RtlAdjustPrivilege`, then
// calls `NtRaiseHardError` with a fatal status code. The kernel responds by
// crashing the system with the supplied bug-check code. Used when an
// operator wants to terminate evidence collection in flight: the in-memory
// state vanishes faster than any forensic agent can flush it, and the
// running process disappears with the kernel.
//
// # MITRE ATT&CK
//
//   - T1529 (System Shutdown/Reboot)
//
// # Detection level
//
// very-noisy
//
// The crash itself is the artifact. Crash dump analysis recovers the
// originating process; `RtlAdjustPrivilege` may be logged by EDR before the
// crash. Use only when the trade-off is acceptable.
//
// # Example
//
// See [ExampleTrigger] in bsod_example_test.go. The example is build-tag
// gated and does NOT run by default — invoking it really crashes the host.
//
// # See also
//
//   - docs/techniques/cleanup/bsod.md
package bsod
