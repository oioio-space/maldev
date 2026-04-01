//go:build windows

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
package blockdlls
