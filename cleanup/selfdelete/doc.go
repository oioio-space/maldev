//go:build windows

// Package selfdelete provides self-deletion techniques for running executables
// on Windows using NTFS alternate data streams and other methods.
//
// Technique: NTFS ADS rename + delete-on-close, batch script loop, MoveFileEx reboot.
// MITRE ATT&CK: T1070.004 (Indicator Removal: File Deletion)
// Platform: Windows
// Detection: Medium -- ADS manipulation is monitored; batch script deletion is well-known.
//
// Four methods:
//   - Run: rename the default :$DATA stream, then mark for deletion (stealthiest)
//   - RunForce: retry Run with configurable delay (handles file locks)
//   - RunWithScript: spawn a batch script that loops until the process exits
//   - MarkForDeletion: schedule deletion at next reboot via MoveFileEx
package selfdelete
