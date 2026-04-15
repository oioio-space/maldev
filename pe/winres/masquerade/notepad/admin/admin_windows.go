//go:build windows

// Package admin embeds the manifest + icons + VERSIONINFO of notepad.exe
// with requestedExecutionLevel=requireAdministrator (prompts UAC).
//
// Blank-import this package to take on the notepad.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/winres/masquerade/notepad/admin"
//
// MITRE ATT&CK: T1036.005
package admin
