// Package timestomp provides file timestamp manipulation for modifying
// access and modification times to blend artifacts with surrounding files.
//
// Technique: Modify file MAC (Modified/Accessed/Created) timestamps.
// MITRE ATT&CK: T1070.006 (Indicator Removal: Timestomp)
// Platform: Cross-platform
// Detection: Medium -- timestamp anomalies can be detected by forensic tools
// comparing NTFS $STANDARD_INFORMATION vs $FILE_NAME timestamps.
//
// Key features:
//   - Set: change access and modification times to arbitrary values
//   - CopyFrom: clone timestamps from a reference file to a target file
package timestomp
