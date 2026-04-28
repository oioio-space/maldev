// Package driver defines the kernel-memory primitive interfaces
// consumed by EDR-bypass packages that need arbitrary kernel reads
// or writes (kcallback, lsassdump PPL-bypass, callback-array
// tampering, …). Concrete BYOVD drivers implement the interfaces
// from sub-packages; the umbrella package owns only the contracts
// and shared sentinel errors.
//
// Interface surface:
//
//   - [Reader] — `ReadKernel(addr, buf) (int, error)`. Wide enough to
//     plug straight into [github.com/oioio-space/maldev/evasion/kcallback].KernelReader.
//   - [ReadWriter] — extends Reader with `WriteKernel(addr, data)`.
//   - [Lifecycle] — `Install / Uninstall / Loaded`. Idempotent install,
//     best-effort uninstall (always cleans up partial state).
//
// Sentinel errors:
//
//   - [ErrNotImplemented] — primitive not exposed by the concrete driver.
//   - [ErrNotLoaded] — call landed before Install completed successfully.
//   - [ErrPrivilegeRequired] — caller lacks SeLoadDriverPrivilege.
//
// Concrete drivers ship as sub-packages keyed by the vulnerable signed
// driver they exploit:
//
//   - [github.com/oioio-space/maldev/kernel/driver/rtcore64] — MSI
//     Afterburner RTCore64.sys (CVE-2019-16098). Microsoft-attested
//     signed binary; HVCI-friendly on Win10 builds prior to the
//     2021-09 vulnerable-driver block-list bump.
//
// # MITRE ATT&CK
//
//   - T1014 (Rootkit) — driver-mode access enablement
//   - T1543.003 (Create or Modify System Process: Windows Service) — service install path
//   - T1068 (Exploitation for Privilege Escalation) — when paired with the IOCTL surface
//
// # Detection level
//
// very-noisy (during install)
// moderate (steady state)
//
// `NtLoadDriver` / SCM `CreateService` + `StartService` are heavily
// monitored — Defender, ESET, Sentinel all hook them. Once the
// driver is loaded, steady-state traffic is just IOCTLs to the
// service handle: noise scales to whether the specific driver name
// (`RTCore64`, `gdrv`, `pcdsrvc`) is on the EDR's known-IOCs list.
//
// # Example
//
// See [github.com/oioio-space/maldev/kernel/driver/rtcore64] for an
// end-to-end Install → ReadKernel → Uninstall example.
//
// # See also
//
//   - docs/techniques/kernel/README.md
//   - [github.com/oioio-space/maldev/evasion/kcallback] — kernel-callback array tampering consumer
//   - [github.com/oioio-space/maldev/credentials/lsassdump] — PPL-bypass primitive consumer
//
// [github.com/oioio-space/maldev/kernel/driver/rtcore64]: https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver/rtcore64
// [github.com/oioio-space/maldev/evasion/kcallback]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/kcallback
// [github.com/oioio-space/maldev/credentials/lsassdump]: https://pkg.go.dev/github.com/oioio-space/maldev/credentials/lsassdump
package driver
