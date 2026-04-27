// Package registry implements Windows registry Run / RunOnce
// key persistence — the canonical "auto-launch on logon" hook.
//
// Writes a named string value under the Run or RunOnce key in
// either HKCU (current user) or HKLM (local machine). The value
// typically contains the full path to an executable plus
// optional arguments. Windows automatically launches programs
// listed in Run keys at user logon; RunOnce entries are deleted
// after their first execution.
//
// HKLM keys require elevated privileges; HKCU keys persist only
// for the current user but do not require elevation.
//
// Registered Run-key paths:
//
//   - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
//   - HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
//   - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
//   - HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
//
// # MITRE ATT&CK
//
//   - T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)
//
// # Detection level
//
// moderate
//
// Run keys are commonly monitored by EDR — Defender for
// Endpoint and most enterprise EDRs ship default rules on
// HKLM\…\Run. HKCU\…\Run carries less default coverage; both
// surface in `autoruns`. Operators wanting lower noise pick
// HKCU on a target where the implant only needs current-user
// access.
//
// # Example
//
// See [ExampleRunKey] in registry_example_test.go.
//
// # See also
//
//   - docs/techniques/persistence/registry.md
//   - [github.com/oioio-space/maldev/persistence/startup] — sibling autostart mechanism
//   - [github.com/oioio-space/maldev/cleanup] — remove the Run-key value post-op
//
// [github.com/oioio-space/maldev/persistence/startup]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup
// [github.com/oioio-space/maldev/cleanup]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup
package registry
