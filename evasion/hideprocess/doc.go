// Package hideprocess patches NtQuerySystemInformation in a target process
// so it returns STATUS_NOT_IMPLEMENTED, blinding that process's ability to
// enumerate running processes. Typically applied to taskmgr.exe or procexp.exe.
//
// MITRE ATT&CK: T1564.001 — Hide Artifacts: Hidden Process
// Detection: Medium (memory write to ntdll detectable via integrity checks)
//
// Example:
//
//	pid := 1234 // target process PID (e.g., taskmgr.exe)
//	if err := hideprocess.PatchProcessMonitor(pid, nil); err != nil {
//	    log.Fatal(err)
//	}
package hideprocess
