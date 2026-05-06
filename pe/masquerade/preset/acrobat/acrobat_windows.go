//go:build windows

// Package acrobat embeds the manifest + icons + VERSIONINFO of acrobat.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the acrobat.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/acrobat"
//
// MITRE ATT&CK: T1036.005
package acrobat
