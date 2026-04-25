// Package bsod triggers a Blue Screen of Death via NtRaiseHardError.
//
// Technique: System crash via NtRaiseHardError (Blue Screen of Death)
// MITRE ATT&CK: T1529 (System Shutdown/Reboot)
// Platform: Windows
// Detection: Low — the crash itself is the detection; crash dump analysis
// may reveal the originating process. RtlAdjustPrivilege call may be
// logged by EDR.
//
// How it works: Enables SeShutdownPrivilege via RtlAdjustPrivilege, then
// calls NtRaiseHardError with a fatal error code. This triggers an
// unrecoverable system crash (BSOD) with the specified error code.
// Use with extreme caution — this is a destructive, irreversible action.
package bsod
