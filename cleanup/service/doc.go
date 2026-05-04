//go:build windows

// Package service hides Windows services from listing utilities by applying
// a restrictive DACL on the service object.
//
// HideService writes a Discretionary Access Control List that denies
// `SERVICE_QUERY_CONFIG`, `SERVICE_QUERY_STATUS`, and related rights to
// Interactive Users, Service accounts, and Administrators while leaving
// minimal access for the SCM. UnHideService restores the default DACL. Two
// application modes:
//
//   - Native — direct call to `SetNamedSecurityInfo`.
//   - SC_SDSET — invokes `sc.exe sdset`, which accepts a remote hostname.
//
// # MITRE ATT&CK
//
//   - T1564 (Hide Artifacts)
//   - T1543.003 (Create or Modify System Process: Windows Service)
//
// # Detection level
//
// noisy
//
// DACL changes on services emit Security event 4670 when SACL auditing is
// enabled. Sysmon Event 4697 logs the service control change.
//
// # Required privileges
//
// admin. `SetNamedSecurityInfo` on a service object needs
// `WRITE_DAC` on the SCM service handle, which is gated on
// membership in the local Administrators group (or
// `SeTakeOwnershipPrivilege` if the implant first reassigns
// ownership). The `SC_SDSET` mode invokes `sc.exe` and
// inherits the same gate. SYSTEM works without elevation.
//
// # Platform
//
// Windows-only (`//go:build windows`). The SCM is a Windows-only
// subsystem; the API set has no POSIX equivalent.
//
// # Example
//
// See [ExampleHideService] in service_example_test.go.
//
// # See also
//
//   - docs/techniques/cleanup/service.md
//   - [github.com/oioio-space/maldev/persistence/service] — install/start side
//
// [github.com/oioio-space/maldev/persistence/service]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/service
package service
