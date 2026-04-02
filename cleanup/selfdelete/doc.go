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
//
// How it works: On NTFS, every file has a default unnamed data stream (:$DATA).
// The technique opens the running executable, renames its default data stream
// to a throwaway name (e.g., ":x"), and then closes and reopens the file with
// DELETE disposition. Because the renamed stream no longer occupies the default
// data stream slot, Windows considers the file "empty" and allows deletion even
// while the process is still running from the original mapped pages in memory.
package selfdelete
