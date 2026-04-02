// Package enum provides cross-platform process enumeration for listing
// and searching running processes by name or PID.
//
// Technique: Process Discovery
// MITRE ATT&CK: T1057 (Process Discovery)
// Platform: Cross-platform (Windows and Linux)
// Detection: Low -- uses standard OS APIs (CreateToolhelp32Snapshot on Windows, /proc on Linux)
//
// Platform-specific implementations:
//   - Windows: uses CreateToolhelp32Snapshot with TH32CS_SNAPPROCESS
//   - Linux: reads /proc/[0-9]*/comm and /proc/[0-9]*/status
//
// Example:
//
//	procs, _ := enum.FindByName("explorer.exe")
//	for _, p := range procs {
//	    fmt.Printf("PID=%d PPID=%d\n", p.PID, p.PPID)
//	}
package enum
