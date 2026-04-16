//go:build windows

// Package admin embeds the manifest + icons + VERSIONINFO of taskmgr.exe
// with requestedExecutionLevel=requireAdministrator (prompts UAC).
//
// Blank-import this package to take on the taskmgr.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/taskmgr/admin"
//
// MITRE ATT&CK: T1036.005
package admin
