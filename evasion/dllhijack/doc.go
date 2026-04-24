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
// Scope (v0.12.2): service-scoped discovery only — ScanServices()
// enumerates every installed service and flags those whose binary
// directory is writable by the current user. Process and scheduled-task
// scanning, PE-imports analysis, and canary-DLL validation are deferred.
//
// Example:
//
//	opps, err := dllhijack.ScanServices()
//	if err != nil { log.Fatal(err) }
//	for _, o := range opps {
//	    fmt.Printf("%s (%s) → %s writable\n", o.ID, o.DisplayName, o.SearchDir)
//	}
package dllhijack
