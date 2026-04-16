//go:build windows

// Package notepad embeds the manifest + icons + VERSIONINFO of notepad.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the notepad.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/notepad"
//
// MITRE ATT&CK: T1036.005
package notepad
