// Package drive provides drive detection, monitoring, and volume information
// retrieval for Windows systems.
//
// Technique: Logical drive enumeration and volume fingerprinting.
// MITRE ATT&CK: T1120 (Peripheral Device Discovery)
// Detection: Low — drive enumeration is standard system behavior.
// Platform: Windows.
//
// How it works: Enumerates logical drives via GetLogicalDrives (bitmask of
// A:-Z:), queries each drive's type with GetDriveTypeW, and retrieves volume
// metadata (name, serial number, filesystem) with GetVolumeInformationW.
// A polling-based watcher detects newly connected removable/network drives
// by comparing successive snapshots.
//
// Key features:
//   - Enumerate logical drives and their types (fixed, removable, network, etc.)
//   - Retrieve volume information (name, serial number, filesystem)
//   - Monitor for newly connected drives with configurable polling interval
//   - Filter drives by type using callback functions
//   - Unique drive ID (MD5 of type + serial + filesystem) for deduplication
//
// Limitations:
//   - Polling-based detection (not event-driven) — default 200ms interval.
//   - Volume serial number may be 0 for some virtual drives.
//   - WatchNew goroutine runs until context is cancelled.
//
// Example:
//
//	drives := drive.NewDrives(ctx)
//	all, _ := drives.All(func(d *drive.Drive) bool {
//	    return d.Type == drive.Removable
//	})
package drive
