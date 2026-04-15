//go:build windows

// Package explorer embeds the manifest + icons + VERSIONINFO of explorer.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the explorer.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/winres/masquerade/explorer"
//
// MITRE ATT&CK: T1036.005
package explorer
