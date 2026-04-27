//go:build windows

// Package acg enables Arbitrary Code Guard for the current process so
// the kernel refuses any further `VirtualAlloc(PAGE_EXECUTE)` /
// `VirtualProtect(PAGE_EXECUTE)` requests.
//
// ACG (`ProcessDynamicCodePolicy`) is a Windows mitigation that
// prevents dynamic code generation. Once enabled, EDR/AV products
// can't inject monitoring trampolines into the process and JIT
// compilers stop working — useful both as defensive hardening and as
// an offensive blinding technique for processes that finished
// allocating their executable pages.
//
// > Apply ACG **after** any payload allocation has completed. The
// > policy is one-way; you cannot relax it for the process lifetime.
//
// # MITRE ATT&CK
//
//   - T1562.001 (Impair Defenses: Disable or Modify Tools)
//
// # Detection level
//
// quiet
//
// `SetProcessMitigationPolicy` is logged by ETW Threat Intelligence;
// the policy itself is a legitimate hardening feature so the signal is
// low.
//
// # Example
//
// See [ExampleEnable] in acg_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/acg-blockdlls.md
//   - [github.com/oioio-space/maldev/evasion/blockdlls] — sibling mitigation
//
// [github.com/oioio-space/maldev/evasion/blockdlls]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/blockdlls
package acg
