//go:build windows

// Package selfdelete deletes the running executable from disk while the
// process continues to execute from its mapped image.
//
// On NTFS, every file has a default unnamed `:$DATA` stream. The core
// technique opens the running executable with DELETE access, renames the
// default stream to a throwaway name (`:x`), and then sets a delete
// disposition on the handle. Windows considers the file "empty" once the
// default stream is renamed, so it tolerates deletion of the running EXE.
// The mapped image stays valid in process memory.
//
// Four entry points trade stealth for portability:
//
//   - Run — the canonical ADS-rename + delete-on-close path. Quietest.
//   - RunForce — Run with retry/duration, for transient lock cases.
//   - RunWithScript — spawn a batch script that polls until the process
//     exits, then deletes. Works without ADS support but is signature-noisy.
//   - MarkForDeletion — schedule deletion at the next reboot via
//     `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`. No on-disk write but the
//     PendingFileRenameOperations registry key holds the artifact.
//
// # MITRE ATT&CK
//
//   - T1070.004 (Indicator Removal: File Deletion)
//
// # Detection level
//
// moderate
//
// ADS rename + DELETE on a running executable is unusual; EDR with MFT
// awareness can flag the rename event. Batch-script variant is a known
// signature.
//
// # Example
//
// See [ExampleRun] in selfdelete_example_test.go.
//
// # See also
//
//   - docs/techniques/cleanup/self-delete.md
//   - [github.com/oioio-space/maldev/cleanup/ads] — building block
//
// [github.com/oioio-space/maldev/cleanup/ads]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads
package selfdelete
