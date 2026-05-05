//go:build windows

// Package onedrive embeds the manifest + icons + VERSIONINFO of onedrive.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the onedrive.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/onedrive"
//
// MITRE ATT&CK: T1036.005
package onedrive
