// Package sandbox is the multi-factor sandbox / VM /
// analysis-environment detector — a configurable orchestrator
// that aggregates checks across `recon/antidebug`,
// `recon/antivm`, and its own primitives into a single
// "is this a sandbox?" assessment.
//
// Aggregated checks:
//
//   - Debugger detection (via recon/antidebug).
//   - VM / hypervisor detection (via recon/antivm).
//   - Hardware thresholds (CPU core count, RAM, disk space).
//   - Suspicious usernames + hostnames (sandbox-typical names).
//   - Analysis-tool process names (Wireshark, ProcMon, IDA, x64dbg).
//   - Fake-domain DNS interception (sandboxes often resolve
//     unknown domains to a sinkhole — query a random domain
//     and see what comes back).
//   - Time-based evasion via CPU-burning waits ([recon/timing]).
//
// `New(cfg)` builds a [Checker]; `IsSandboxed(ctx)` runs the
// full assessment and returns (is-sandbox, reason, err). Use
// [DefaultConfig] for the canonical defender baseline,
// override individual fields for stricter or looser criteria.
//
// # MITRE ATT&CK
//
//   - T1497 (Virtualization/Sandbox Evasion)
//
// # Detection level
//
// quiet
//
// Individual checks are benign (every game / installer / DRM
// runs them). Combined behaviour — fast successive checks
// against multiple dimensions — may be flagged by behavioural
// EDR but rarely is in practice.
//
// # Required privileges
//
// unprivileged. Each underlying check
// (`recon/antidebug`, `recon/antivm`, `recon/timing`,
// process / hostname / DNS reads) runs in any token; the
// scoring orchestrator adds no extra gate.
//
// # Platform
//
// Cross-platform. Wraps the cross-platform `recon/*`
// primitives + stdlib `net` for fake-DNS interception.
// Per-check coverage matches each underlying package's
// platform support (debugger / VM detection are
// Windows + Linux; some hardware checks degrade on
// macOS).
//
// # Example
//
// See [ExampleNew] in sandbox_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/sandbox.md
//   - [github.com/oioio-space/maldev/recon/antidebug] / [github.com/oioio-space/maldev/recon/antivm] — primitives consumed here
//   - [github.com/oioio-space/maldev/recon/timing] — sibling time-based evasion
//
// [github.com/oioio-space/maldev/recon/antidebug]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/antidebug
// [github.com/oioio-space/maldev/recon/antivm]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm
// [github.com/oioio-space/maldev/recon/timing]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/timing
package sandbox
