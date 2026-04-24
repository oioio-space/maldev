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
//   - ScanServices() enumerates every installed Windows service, parses
//     its binary's PE import table, resolves the DLL search order, and
//     emits one Opportunity per (service, importedDLL) pair where a
//     user-writable directory sits EARLIER in the search order than the
//     DLL's legitimate location. Each Opportunity names the exact DLL
//     and drop path — no "writable dir alone" false positives.
//   - SearchOrder / HijackPath are the reusable primitives the scanner
//     uses; callers can invoke them directly on any (exe, dll) pair.
//   - KnownDLLs (HKLM\...\Session Manager\KnownDLLs) are correctly
//     excluded from hijack candidates.
//
// Deferred: ScanProcesses (Toolhelp32 module walk), ScanScheduledTasks
// (COM ITaskService), canary-DLL generation + validation, AutoElevate
// scoring.
//
// Example:
//
//	opps, err := dllhijack.ScanServices()
//	if err != nil { log.Fatal(err) }
//	for _, o := range opps {
//	    fmt.Printf("%s (%s) → drop %s (instead of %s)\n",
//	        o.ID, o.DisplayName, o.HijackedPath, o.ResolvedDLL)
//	}
package dllhijack
