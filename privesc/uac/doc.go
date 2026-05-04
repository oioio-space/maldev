//go:build windows

// Package uac implements four classic UAC-bypass primitives that
// hijack auto-elevating Windows binaries to spawn an elevated
// process without a consent prompt.
//
// All four exported entry points are register → trigger → cleanup
// chains: install a registry hijack under HKCU, launch the
// auto-elevating binary so it inherits the elevated token while
// reading the hijacked key, then remove the hijack on a deferred
// path. The supplied `path` is the command that executes elevated.
//
// Methods:
//
//   - [FODHelper] — abuses `fodhelper.exe`'s `ms-settings\CurVer`
//     delegation. Windows 10+ on default-UAC posture.
//   - [SLUI] — abuses `slui.exe`'s `exefile\shell\open\command`
//     delegation.
//   - [SilentCleanup] — abuses the `SilentCleanup` Scheduled Task's
//     `windir` environment-variable expansion.
//   - [EventVwr] — abuses `eventvwr.exe`'s `mscfile\shell\open\command`
//     delegation.
//   - [EventVwrLogon] — `EventVwr` + alternate credentials via
//     `CreateProcessWithLogonW` (Secondary Logon service).
//
// All five hijack auto-elevation behaviour, so they require:
//
//   - Caller already running as a member of Administrators (UAC
//     downgrades elevation under "Default" but not when the user
//     isn't admin).
//   - UAC level not "Always notify" — the prompt cannot be silenced
//     at that level.
//
// Pair with [github.com/oioio-space/maldev/win/version] for build
// gating: hijack keys move across builds (FODHelper survived 1903 →
// 22H2; EventVwr blocked from 17134+).
//
// # MITRE ATT&CK
//
//   - T1548.002 (Bypass User Account Control)
//
// # Detection level
//
// noisy
//
// Registry writes under `HKCU\Software\Classes\<scheme>` followed by
// auto-elevated binary launch is a textbook EDR detection — every
// vendor ships a rule for this exact pattern. The window between
// hijack registration and cleanup is small (sub-second), but the
// process-tree anomaly (`fodhelper.exe` parent of `cmd.exe` is rare
// in non-attacker telemetry) lights up behavioural detectors.
//
// # Required privileges
//
// medium-IL caller already in the local Administrators
// group. Counter-intuitively, UAC-bypass elevates an
// already-admin user from a filtered (non-elevated)
// token to a full admin token without prompting — it
// does NOT escalate from a standard user. UAC level
// must NOT be "Always notify" (the prompt cannot be
// silenced at that level). All five primitives write
// `HKCU\Software\Classes\<scheme>` (per-user, no extra
// privilege beyond own-hive write).
//
// # Platform
//
// Windows-only (`//go:build windows`). The auto-elevate
// binaries (`fodhelper.exe`, `slui.exe`, `eventvwr.exe`)
// and the `SilentCleanup` Scheduled Task are all
// Windows-specific.
//
// # Example
//
// See [ExampleFODHelper] in uac_example_test.go.
//
// # See also
//
//   - docs/techniques/privesc/uac.md
//   - [github.com/oioio-space/maldev/win/privilege] — `IsAdmin` / `ExecAs` complement
//   - [github.com/oioio-space/maldev/win/version] — build gating before chosen bypass
//
// [github.com/oioio-space/maldev/win/privilege]: https://pkg.go.dev/github.com/oioio-space/maldev/win/privilege
// [github.com/oioio-space/maldev/win/version]: https://pkg.go.dev/github.com/oioio-space/maldev/win/version
package uac
