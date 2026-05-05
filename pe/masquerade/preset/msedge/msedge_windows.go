//go:build windows

// Package msedge embeds the manifest + icons + VERSIONINFO of msedge.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the msedge.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/msedge"
//
// MITRE ATT&CK: T1036.005
package msedge
