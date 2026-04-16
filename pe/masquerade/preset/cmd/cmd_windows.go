//go:build windows

// Package cmd embeds the manifest + icons + VERSIONINFO of cmd.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the cmd.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/cmd"
//
// MITRE ATT&CK: T1036.005
package cmd
