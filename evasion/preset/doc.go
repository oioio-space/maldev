// Package preset provides ready-to-use evasion technique combinations.
//
// Three presets are available:
//
//   - Minimal: patches AMSI + ETW (least detectable)
//   - Stealth: Minimal + unhook commonly hooked NT functions
//   - Aggressive: everything including full ntdll unhook + ACG + blockdlls
//
// Example:
//
//	cfg := &shell.Config{
//	    Evasion: preset.Stealth(),
//	}
package preset
