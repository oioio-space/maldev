// Package fakecmd overwrites the current process PEB CommandLine string so
// that process-listing tools (Process Explorer, wmic, Get-Process) display a
// fake command line rather than the real one.
//
// MITRE ATT&CK: T1036.005 — Masquerading: Match Legitimate Name or Location
// Detection: Low (in-memory only; kernel EPROCESS retains original)
//
// Example:
//
//	if err := fakecmd.Spoof(`C:\Windows\System32\svchost.exe -k netsvcs`, nil); err != nil {
//	    log.Fatal(err)
//	}
//	defer fakecmd.Restore()
package fakecmd
