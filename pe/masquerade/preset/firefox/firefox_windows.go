//go:build windows

// Package firefox embeds the manifest + icons + VERSIONINFO of firefox.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the firefox.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/firefox"
//
// MITRE ATT&CK: T1036.005
package firefox
