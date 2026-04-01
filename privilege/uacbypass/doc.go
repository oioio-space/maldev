//go:build windows

// Package uacbypass implements UAC (User Account Control) bypass techniques
// for executing programs with elevated privileges without a UAC prompt.
//
// Technique: Registry key manipulation to hijack auto-elevating Windows binaries.
// MITRE ATT&CK: T1548.002 (Abuse Elevation Control Mechanism: Bypass UAC)
// Platform: Windows
// Detection: High -- registry modifications and auto-elevate abuse are well-known indicators.
//
// Four bypass methods:
//   - FODHelper: abuses fodhelper.exe ms-settings CurVer delegation (Windows 10+)
//   - SLUI: abuses slui.exe exefile shell open command
//   - SilentCleanup: abuses SilentCleanup scheduled task windir variable
//   - EventVwr: abuses eventvwr.exe mscfile shell open command
//
// EventVwrLogon variant uses CreateProcessWithLogonW for alternate credentials.
package uacbypass
