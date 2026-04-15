//go:build windows

// Package taskmgr embeds the manifest + icons + VERSIONINFO of taskmgr.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the taskmgr.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/winres/masquerade/taskmgr"
//
// MITRE ATT&CK: T1036.005
package taskmgr
