// Package amsi provides AMSI (Antimalware Scan Interface) bypass techniques
// through runtime memory patching of amsi.dll functions.
//
// Technique: Runtime memory patching of AmsiScanBuffer and AmsiOpenSession.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
// Platform: Windows
// Detection: Medium -- EDR may monitor VirtualProtect on amsi.dll pages.
//
// Two bypass methods:
//   - PatchScanBuffer: overwrites AmsiScanBuffer entry to return E_INVALIDARG,
//     making AMSI report all scans as clean.
//   - PatchOpenSession: flips a conditional jump (JZ to JNZ) in AmsiOpenSession,
//     preventing AMSI session initialization.
//   - PatchAll: applies both patches in sequence.
//
// Returns nil if amsi.dll is not loaded (nothing to patch).
//
// How it works: AMSI is a Windows interface that allows antivirus engines to
// scan scripts and .NET assemblies at runtime before they execute. Offensive
// tools patch AMSI to prevent detection of in-memory payloads that would
// otherwise be flagged. The patch overwrites the first few bytes of
// AmsiScanBuffer's entry point so the function returns immediately with a
// benign result, causing the AV engine to never see the content being scanned.
package amsi
