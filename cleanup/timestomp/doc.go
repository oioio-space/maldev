// Package timestomp resets a file's NTFS `$STANDARD_INFORMATION` timestamps
// so a dropped artifact blends with surrounding files.
//
// Two entry points:
//
//   - Set — assign arbitrary access/modification times.
//   - CopyFrom — clone timestamps from a reference file. Useful for
//     blending an implant into `C:\Windows\System32\` by cloning
//     `notepad.exe` MAC times.
//
// On NTFS, each file has two timestamp records: `$STANDARD_INFORMATION`
// (read by Explorer / `dir` / most APIs) and `$FILE_NAME` (maintained by
// the filesystem driver, only writable from kernel mode). The standard
// `SetFileTime` API touches `$STANDARD_INFORMATION` only. Forensic tools
// (Sleuth Kit, Plaso) compare the two — disparity is the canonical
// timestomping signal.
//
// # MITRE ATT&CK
//
//   - T1070.006 (Indicator Removal: Timestomp)
//
// # Detection level
//
// quiet
//
// Standard-information modification leaves no event-log entry. Detection
// requires forensic-grade MFT comparison.
//
// # Example
//
// See [ExampleSet] and [ExampleCopyFrom] in timestomp_example_test.go.
//
// # See also
//
//   - docs/techniques/cleanup/timestomp.md
package timestomp
