// Package rtcore64 wraps the MSI Afterburner RTCore64.sys signed
// driver (CVE-2019-16098) as a [kernel/driver.ReadWriter] primitive.
// The driver exposes IOCTLs that read and write arbitrary kernel
// virtual addresses, enabling SeDebugPrivilege-equivalent kernel
// access without loading an unsigned driver.
//
// The [Driver] type implements both [kernel/driver.ReadWriter] and
// [kernel/driver.Lifecycle], so callers can manage install/start/stop
// uniformly across BYOVD primitives. Driver bytes are NOT embedded
// by default — opt in by building with the `byovd_rtcore64` build
// tag and providing a gitignored `embed_windows.go` that exposes the
// driver via `embed.FS`. This keeps the open-source repo free of
// MSI-redistribution concerns.
//
// Use cases:
//
//   - Read kernel memory for [github.com/oioio-space/maldev/credentials/lsassdump]
//     PPL-bypass — the driver primitive sidesteps RtlpAdjustTokenPrivileges'
//     PPL gate.
//   - Wipe kernel-callback arrays via
//     [github.com/oioio-space/maldev/evasion/kcallback] (PsSetCreateProcessNotifyRoutine,
//     ObRegisterCallbacks).
//
// BYOVD posture:
//
//   - Loads on Win10/11 with HVCI off, and on Win10 builds prior to
//     the 2021-09-02 Microsoft vulnerable-driver block-list update.
//   - On HVCI-on / patched builds, [Driver.Install] returns
//     `STATUS_ACCESS_DENIED` from `NtLoadDriver`.
//
// # MITRE ATT&CK
//
//   - T1014 (Rootkit) — kernel-mode access enablement
//   - T1543.003 (Create or Modify System Process: Windows Service) — `RTCore64` service registration
//   - T1068 (Exploitation for Privilege Escalation) — IOCTL-driven arbitrary kernel R/W
//
// # Detection level
//
// very-noisy (during Install) → moderate (steady state)
//
// `NtLoadDriver` + `CreateService` + `StartService` are heavily
// monitored. Once loaded, steady-state detection drops to MEDIUM —
// the driver is signed Microsoft-attested, but its service handle
// name `RTCore64` is on every vendor's known-IOCs list as of 2024+.
//
// # Example
//
// See [ExampleDriver_Install] and [ExampleDriver_ReadKernel] in
// rtcore64_example_test.go.
//
// # See also
//
//   - docs/techniques/kernel/byovd-rtcore64.md
//   - [github.com/oioio-space/maldev/evasion/kcallback] — kernel-callback tampering consumer
//   - [github.com/oioio-space/maldev/credentials/lsassdump] — PPL-bypass consumer
//
// [github.com/oioio-space/maldev/evasion/kcallback]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/kcallback
// [github.com/oioio-space/maldev/credentials/lsassdump]: https://pkg.go.dev/github.com/oioio-space/maldev/credentials/lsassdump
package rtcore64
