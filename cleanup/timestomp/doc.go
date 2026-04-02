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
//
// How it works: Timestomping modifies file timestamps (creation, modification,
// access) to make a dropped artifact appear as if it has existed on disk since
// the OS installation or some other innocuous date. On NTFS, each file has two
// timestamp records: $STANDARD_INFORMATION (used by Explorer and dir) and
// $FILE_NAME (maintained by the filesystem driver). Standard APIs like
// SetFileTime only modify $STANDARD_INFORMATION, leaving $FILE_NAME untouched.
// Forensic tools compare the two to detect timestomping, but most casual
// triage and automated tooling only checks $STANDARD_INFORMATION.
package timestomp
