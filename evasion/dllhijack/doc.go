// Package dllhijack discovers DLL-search-order hijack opportunities on
// Windows — places where an application will load a DLL from a
// user-writable directory BEFORE reaching the legitimate copy (typically
// in System32). Drop a DLL with the right name in the writable path and
// your code runs next time the victim loads it.
//
// MITRE ATT&CK: T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking
// Platform: Windows
// Detection: Medium (writes to service dirs + unusual DLL loads are logged
// by most modern EDRs; the unique signal is the mismatch between expected
// DLL location and actual load path)
//
// Scope:
//   - ScanServices parses each service binary's PE import table and emits
//     Opportunities via DLL search-order resolution.
//   - ScanProcesses reads live loaded-module lists from every accessible
//     process (Toolhelp32) — covers runtime LoadLibrary, not just static
//     imports.
//   - ScanScheduledTasks pulls every registered task's exec actions via
//     COM ITaskService and applies the same PE-imports filter to each.
//   - ScanAutoElevate walks System32 .exes whose manifest carries
//     autoElevate=true (fodhelper, sdclt, ...) — UAC bypass vector
//     (MITRE T1548.002).
//   - ScanAll aggregates the four.
//   - Validate drops a user-supplied canary DLL at an Opportunity's
//     HijackedPath, triggers the victim, polls for a marker file, and
//     cleans up.
//   - Rank scores Opportunities (higher = more impact: AutoElevate +
//     IntegrityGain weighted heavily).
//   - SearchOrder / HijackPath / IsAutoElevate are the primitives
//     callers can invoke on any (exe, dll) pair or raw PE bytes.
//   - KnownDLLs (HKLM\...\Session Manager\KnownDLLs) are correctly
//     excluded from hijack candidates.
//
// Example:
//
//	all, err := dllhijack.ScanAll()
//	if err != nil { log.Print(err) /* partial failures OK */ }
//	for _, o := range all {
//	    fmt.Printf("%s[%s] %s → drop %s (instead of %s)\n",
//	        o.Kind, o.ID, o.DisplayName, o.HijackedPath, o.ResolvedDLL)
//	}
package dllhijack
