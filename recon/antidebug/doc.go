// Package antidebug detects whether a debugger is currently
// attached to the implant — Windows via `IsDebuggerPresent`
// (PEB BeingDebugged), Linux via `/proc/self/status TracerPid`.
//
// Cross-platform single-call surface: [IsDebuggerPresent] returns
// a bool. Pair with [github.com/oioio-space/maldev/recon/sandbox]
// for multi-factor sandbox / analysis-environment detection.
//
// # MITRE ATT&CK
//
//   - T1622 (Debugger Evasion)
//
// # Detection level
//
// quiet
//
// Reading the PEB BeingDebugged flag is invisible — every
// runtime / framework / DRM library does it. `/proc/self/status`
// reads on Linux are equally common.
//
// # Example
//
// See [ExampleIsDebuggerPresent] in antidebug_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/anti-analysis.md
//   - [github.com/oioio-space/maldev/recon/sandbox] — multi-factor orchestrator
//   - [github.com/oioio-space/maldev/recon/antivm] — sibling VM detection
//
// [github.com/oioio-space/maldev/recon/sandbox]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/sandbox
// [github.com/oioio-space/maldev/recon/antivm]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm
package antidebug
