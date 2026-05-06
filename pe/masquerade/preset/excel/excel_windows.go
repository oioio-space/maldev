//go:build windows

// Package excel embeds the manifest + icons + VERSIONINFO of excel.exe
// with requestedExecutionLevel=asInvoker.
//
// Blank-import this package to take on the excel.exe identity:
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/excel"
//
// MITRE ATT&CK: T1036.005
package excel
