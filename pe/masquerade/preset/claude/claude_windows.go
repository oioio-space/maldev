//go:build windows

// Package claude embeds the manifest + icons + VERSIONINFO of claude.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the claude.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/claude"
//
// MITRE ATT&CK: T1036.005
package claude
