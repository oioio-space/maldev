// Package imports provides cross-platform PE import table analysis.
//
// Technique: Parse PE import directory to enumerate DLL dependencies and imported function names.
// MITRE ATT&CK: T1106 — Native API (discovery of imported APIs).
// Platform: Cross-platform (operates on PE bytes).
// Detection: N/A — static analysis only.
//
// Example:
//
//	imps, _ := imports.List(`C:\Windows\System32\notepad.exe`)
//	for _, imp := range imps {
//	    fmt.Printf("%s!%s\n", imp.DLL, imp.Function)
//	}
package imports
