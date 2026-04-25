// Package driver defines the kernel-memory primitive interfaces consumed
// by EDR-bypass packages that need arbitrary kernel reads or writes
// (kcallback, lsassdump PPL-bypass, callback-array tampering, etc.).
//
// Concrete primitives ship in sub-packages keyed by the vulnerable
// signed driver they exploit:
//
//   - kernel/driver/rtcore64 — MSI Afterburner RTCore64.sys
//     (CVE-2019-16098). Ships as a Microsoft-attested signed
//     binary; HVCI-friendly on Win10 builds prior to the 2021-09
//     vulnerable-driver block-list bump.
//
// MITRE ATT&CK: T1014 (Rootkit) — driver-mode access enablement, plus
// T1543.003 (Create or Modify System Process: Windows Service) for the
// service install path BYOVD primitives use.
//
// Detection: HIGH during driver load on Win10/11 with HVCI enabled —
// the attested-driver block-list refuses RTCore64 as of mid-2021 and
// EDRs hook NtLoadDriver / NtSetSystemInformation. Once loaded, the
// driver itself is signed Microsoft, so steady-state detection drops
// to MEDIUM (vendor heuristics on RTCore64 service handles).
//
// Layering: this package sits at Layer 1 (close to win/api). Only
// depends on win/api + golang.org/x/sys/windows. Sub-packages may add
// driver-specific deps (e.g. embed.FS for the signed driver bytes,
// behind a build tag).
package driver
