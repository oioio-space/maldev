// Package winres groups blank-importable sub-packages that embed Windows
// PE resources (manifest, icon, version info) into the final binary at
// link time via .syso object files.
//
// Blank-importing ONE sub-package from this tree produces a Windows binary
// whose VERSIONINFO, icons and application manifest mimic a chosen target
// application (masquerading) and/or carry a specific UAC execution level.
//
// Layout:
//
//	pe/winres/masquerade/<identity>/          — identity invoker UAC (default)
//	pe/winres/masquerade/<identity>/admin/    — identity + requireAdministrator
//
// Current identities: cmd, svchost, taskmgr, explorer, notepad.
//
// Example:
//
//	import _ "github.com/oioio-space/maldev/pe/winres/masquerade/cmd"
//
// The resulting executable shows "Windows Command Processor" / Microsoft
// Corp / cmd.exe icon in Task Manager and Process Explorer.
//
// Rule: import AT MOST ONE package from this tree. Windows binaries carry
// exactly one RT_MANIFEST (ID=1) — conflicting blank imports will produce
// a duplicate-symbol linker error.
//
// Technique: Masquerading via PE resource embedding.
// MITRE ATT&CK: T1036.005 — Masquerading: Match Legitimate Name or Location.
// Detection: Low — VERSIONINFO/manifest can be inspected but rarely are.
//
// Regeneration: run
//
//	go run ./pe/winres/internal/gen
//
// on a Windows host. The generator reads the reference executables
// read-only from %SystemRoot%\System32 and recompiles every .syso.
package winres
