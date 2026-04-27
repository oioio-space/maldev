//go:build windows

// Package blockdlls applies the
// `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES`
// mitigation so the loader refuses any DLL that isn't Microsoft-signed.
//
// EDR/AV products often ship a monitoring DLL that they inject into
// new processes via `AppInit_DLLs`, image-load callbacks, or shimming.
// Blocking non-Microsoft DLLs prevents that DLL from loading,
// effectively blinding the user-mode hook layer for the rest of the
// process lifetime.
//
// # MITRE ATT&CK
//
//   - T1562.001 (Impair Defenses: Disable or Modify Tools)
//
// # Detection level
//
// quiet
//
// The mitigation is a legitimate hardening feature, but the
// `SetProcessMitigationPolicy` call is visible to ETW TI. EDRs that
// notice their own DLL failed to load may flag the process.
//
// # Example
//
// See [ExampleEnable] in blockdlls_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/acg-blockdlls.md
//   - [github.com/oioio-space/maldev/evasion/acg] — sibling mitigation
//
// [github.com/oioio-space/maldev/evasion/acg]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/acg
package blockdlls
