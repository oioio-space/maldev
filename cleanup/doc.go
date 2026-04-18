// Package cleanup provides on-host artifact removal and anti-forensics
// utilities used after an operation completes.
//
// Technique: Indicator removal on host -- memory wiping, timestamp reset,
// secure file overwrite, self-deletion, service unregistration.
// MITRE ATT&CK: T1070 (Indicator Removal), T1070.004 (File Deletion),
// T1070.006 (Timestomp), T1564/T1543.003 (service hiding).
// Platform: Cross-platform surface; several sub-packages Windows-only.
// Detection: Low-to-Medium depending on sub-package -- secure wipe leaves no
// file but the wipe activity itself (DeleteFile, SetFileInformationByHandle)
// is audit-loggable.
//
// Sub-packages:
//
//   - cleanup/memory:     zero sensitive buffers before free (T1070)
//   - cleanup/timestomp:  reset $STANDARD_INFORMATION NTFS timestamps (T1070.006)
//   - cleanup/wipe:       multi-pass overwrite of on-disk files (T1070.004)
//   - cleanup/selfdelete: delete the running executable via NTFS ADS trick
//   - cleanup/service:    hide or unregister Windows services
//
// The umbrella package exports nothing. Import the relevant sub-package.
package cleanup
