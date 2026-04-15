//go:build windows

// Package svchost embeds the manifest + icons + VERSIONINFO of svchost.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the svchost.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/winres/masquerade/svchost"
//
// MITRE ATT&CK: T1036.005
package svchost
