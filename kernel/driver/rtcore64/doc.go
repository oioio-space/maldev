// Package rtcore64 wraps the MSI Afterburner RTCore64.sys signed driver
// (CVE-2019-16098) as a kernel/driver.ReadWriter primitive. The driver
// exposes IOCTLs that read and write arbitrary virtual addresses, which
// lets userland obtain SeDebugPrivilege-equivalent kernel access without
// loading an unsigned driver.
//
// Technique: BYOVD (Bring Your Own Vulnerable Driver). RTCore64 is
// Microsoft-attested and signed, so it loads on Win10/11 with HVCI off
// and on Win10 builds prior to the 2021-09-02 Microsoft vulnerable-
// driver block-list bump. Behavior on patched HVCI builds: NtLoadDriver
// returns STATUS_ACCESS_DENIED at install time.
//
// MITRE ATT&CK: T1014 (Rootkit) + T1543.003 (Create or Modify System
// Process: Windows Service).
//
// Detection: HIGH during driver load (NtLoadDriver / SCM CreateService
// + StartService events; many EDRs hook these explicitly). Once
// loaded, steady-state detection drops to MEDIUM — the driver is signed
// Microsoft-attested but its service handle name "RTCore64" is in
// every vendor's known-IOCs list as of 2024+.
//
// Driver binary: NOT embedded by default. Callers opt in by building
// with the `byovd_rtcore64` build tag and providing the driver bytes via
// kernel/driver/rtcore64/embed_windows.go (gitignored copy). This keeps
// the open-source repo free of MSI-redistribution concerns while still
// shipping the install / IOCTL plumbing.
//
// Platform: Windows amd64 only.
package rtcore64
