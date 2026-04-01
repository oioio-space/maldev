// Package drive provides drive detection, monitoring, and volume information
// retrieval for Windows systems.
//
// Platform: Windows (drive detection logic), Cross-platform (types)
// Detection: Low -- drive enumeration is standard system behavior.
//
// Key features:
//   - Enumerate logical drives and their types (fixed, removable, network, etc.)
//   - Retrieve volume information (name, serial number, filesystem)
//   - Monitor for newly connected drives with configurable polling
//   - Filter drives by type using callback functions
//
// Example:
//
//	drives := drive.NewDrives(ctx)
//	all, _ := drives.GetAll(func(d *drive.Drive) bool {
//	    return d.Type == drive.REMOVABLE
//	})
package drive
