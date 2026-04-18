// Package process provides cross-platform process enumeration and management.
//
// Technique: Process enumeration and session discovery.
// MITRE ATT&CK: T1057 (Process Discovery)
// Platform: Cross-platform (Windows, Linux)
// Detection: Low -- enumerating processes is standard operating-system
// behavior used by every task manager.
//
// This is the parent umbrella for:
//
//   - process/enum: find processes by name or predicate
//   - process/session: Windows session/desktop token discovery and remote
//     process creation (T1134.002)
//
// The umbrella package itself exports nothing; import the relevant sub-package.
//
// Example:
//
//	pids, err := enum.FindByName("lsass.exe")
//	if err != nil {
//	    return err
//	}
//	for _, pid := range pids {
//	    fmt.Println(pid)
//	}
package process
