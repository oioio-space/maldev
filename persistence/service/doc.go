// Package service implements Windows service persistence via
// the Service Control Manager — the highest-trust persistence
// mechanism available, running as SYSTEM at boot.
//
// Creates a service entry in the SCM database that starts the
// specified executable automatically on boot (`StartAuto`) or
// on demand (`StartManual`). Requires administrator
// privileges to install. Composes with
// [github.com/oioio-space/maldev/pe/masquerade] to emit a binary
// that renders as a legitimate service host (svchost preset).
//
// # MITRE ATT&CK
//
//   - T1543.003 (Create or Modify System Process: Windows Service)
//
// # Detection level
//
// noisy
//
// Service creation generates System event 7045 ("a service was
// installed") and Security event 4697 ("a service was
// installed"). Services are visible in `services.msc`, `sc query`,
// `Get-Service`, `autoruns`, and `wmic service`. Mature EDR
// stacks correlate 7045 against the binary path and signer —
// SYSTEM-running services pointing at user-writable paths
// (`%TEMP%`, `%APPDATA%`) trip default rules.
//
// # Required privileges
//
// admin. SCM `CreateService` / `DeleteService` / `ChangeService`
// require `SC_MANAGER_CREATE_SERVICE` on the SCM database
// (Administrators only). SYSTEM works without elevation.
// Setting `Config.Account` to a non-default principal
// additionally requires `SeServiceLogonRight` on the target
// account; the package ships `GrantSeServiceLogonRight` to
// satisfy this gate (LSA write — also admin).
//
// # Platform
//
// Windows-only. The SCM is a Windows-only subsystem; no POSIX
// analogue. Linux equivalent (systemd unit installation) is out
// of scope here — see `persistence/doc.go` for the wider
// platform map.
//
// # Example
//
// See [ExampleService] in service_example_test.go.
//
// # See also
//
//   - docs/techniques/persistence/service.md
//   - [github.com/oioio-space/maldev/pe/masquerade] — emit a binary that masquerades as svchost
//   - [github.com/oioio-space/maldev/persistence/scheduler] — sibling persistence with lighter telemetry
//   - [github.com/oioio-space/maldev/cleanup] — remove the service post-op
//
// [github.com/oioio-space/maldev/pe/masquerade]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade
// [github.com/oioio-space/maldev/persistence/scheduler]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/scheduler
// [github.com/oioio-space/maldev/cleanup]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup
package service
