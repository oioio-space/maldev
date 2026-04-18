// Package system provides host information and low-level system utilities:
// drive enumeration, folder path resolution, NTFS alternate data streams,
// LNK shortcut creation, network interface discovery, message boxes, and
// controlled BSOD triggering.
//
// Technique: Host discovery and system artifact manipulation.
// MITRE ATT&CK: T1120 (Peripheral Device Discovery), T1083 (File/Directory
// Discovery), T1564.004 (NTFS File Attributes), T1547.009 (Shortcut
// Modification), T1529 (System Shutdown/Reboot).
// Platform: Cross-platform network utilities; most sub-packages Windows-only.
// Detection: Mostly Low -- these are standard host-inspection APIs.
//
// Sub-packages:
//
//   - system/drive:   volume enumeration + type classification (T1120)
//   - system/folder:  known-folder path resolution via SHGetFolderPath (T1083)
//   - system/ads:     NTFS alternate data stream operations (T1564.004)
//   - system/lnk:     Windows shortcut (.lnk) creation via COM
//   - system/network: network interface IP discovery
//   - system/bsod:    controlled BSOD via NtRaiseHardError (T1529, destructive)
//   - system/ui:      MessageBoxW wrappers (type-safe constants)
//
// The umbrella package exports nothing. Import the relevant sub-package.
package system
