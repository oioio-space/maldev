// Package wipe provides secure file wiping by overwriting file contents
// with random data before deletion.
//
// Technique: Multi-pass random overwrite followed by file removal.
// MITRE ATT&CK: T1070.004 (Indicator Removal: File Deletion)
// Platform: Cross-platform
// Detection: Low -- file writes and deletions are high-volume events.
//
// The File function performs configurable multi-pass overwriting with
// cryptographically random data before calling os.Remove, making forensic
// file recovery significantly more difficult.
package wipe
