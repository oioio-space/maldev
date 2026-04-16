// Package preset provides ready-to-use evasion technique combinations at
// three risk levels: Minimal, Stealth, and Aggressive.
//
// Minimal patches AMSI ScanBuffer + ETW (script/ETW telemetry only).
// Lowest detection surface — suitable for droppers and initial access.
//
// Stealth adds selective ntdll unhooking of ~10 commonly hooked NT functions
// (NtAllocateVirtualMemory, NtCreateThreadEx, etc.). Suitable for
// post-exploitation tools that need injection without inline hook interference.
//
// Aggressive applies full ntdll unhook + ACG + BlockDLLs. Maximum evasion
// but irreversible: ACG blocks subsequent RWX allocation, so apply AFTER
// injection. Suitable for red team finals and assumed-breach scenarios.
//
// Each preset returns []evasion.Technique for use with evasion.ApplyAll().
//
// Example:
//
//	errs := evasion.ApplyAll(preset.Stealth(), nil)
package preset
