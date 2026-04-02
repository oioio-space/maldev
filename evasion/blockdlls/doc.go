// Package blockdlls provides DLL blocking via process mitigation policies
// to prevent non-Microsoft DLLs from being loaded into the process.
//
// Technique: SetProcessMitigationPolicy or PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
// Platform: Windows (10 1709+)
// Detection: Low -- this is a legitimate security hardening feature.
//
// Blocking non-Microsoft-signed DLLs prevents EDR/AV products from injecting
// their monitoring DLLs into the process, effectively blinding user-mode hooks.
//
// How it works: Most EDR products work by injecting a monitoring DLL into every
// new process via mechanisms like AppInit_DLLs or image load callbacks. The
// injected DLL installs inline hooks on ntdll functions to intercept syscalls.
// By enabling the PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES
// policy, Windows refuses to load any DLL that is not signed by Microsoft,
// preventing the EDR's DLL from loading and leaving the process unmonitored.
package blockdlls
