//go:build windows

// Package sevenzip embeds the manifest + icons + VERSIONINFO of sevenzip.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the sevenzip.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/sevenzip"
//
// MITRE ATT&CK: T1036.005
package sevenzip
