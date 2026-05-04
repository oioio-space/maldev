// Package cve202430088 implements CVE-2024-30088 — a Windows kernel
// TOCTOU race in `AuthzBasepCopyoutInternalSecurityAttributes` that
// yields local privilege escalation to NT AUTHORITY\SYSTEM by
// overwriting the calling thread's primary token with `lsass.exe`'s
// SYSTEM token.
//
// Discovery: k0shl (Angelboy) — DEVCORE. Patched in Patch Tuesday
// June 2024 (KB5039211). CVSS 7.0 / CWE-367. Affected: Windows
// 10 1507–22H2, Windows 11 21H2–23H2, Server 2016/2019/2022/2022
// 23H2 prior to June 2024 patch level.
//
// How it works — the kernel reads a user-mode security descriptor,
// validates it, then re-reads to copy. Between the two reads, the
// attacker flips the descriptor pointer to a kernel object,
// triggering an arbitrary kernel write. The write primitive is
// pivoted into a token swap: replace the caller's [_EPROCESS.Token]
// with the SYSTEM token harvested from `lsass.exe`.
//
// API:
//
//   - [Run] — convenience wrapper. Default config; spawns `cmd.exe`
//     under the elevated token on success.
//   - [RunWithExec] — pass [Config] for the post-elevation command
//     (path + argv) and timeout overrides.
//   - [CheckVersion] — pre-flight: verifies the host is in the
//     vulnerable-build window before triggering the race.
//
// Caveat: the race is non-deterministic by design. The exploit
// retries until success or context-cancelled. May BSOD on misfire
// (kernel write lands in invalid memory) — only use in authorised
// engagements where a host crash is acceptable.
//
// # MITRE ATT&CK
//
//   - T1068 (Exploitation for Privilege Escalation) — kernel TOCTOU race
//   - T1134.001 (Token Impersonation/Theft) — SYSTEM token swap
//
// # Detection level
//
// noisy
//
// Repeated `NtAccessCheckByTypeAndAuditAlarm` calls during the race
// window are anomalous. SYSTEM-token swap visible to any EDR
// querying [_EPROCESS.Token] across snapshots. Pre-patch hosts are
// in vendor signature databases as of mid-2024.
//
// # Required privileges
//
// unprivileged. The whole point of the bug is that any
// medium-IL token can win the race and end up SYSTEM —
// no admin, no `SeDebugPrivilege`, no driver load. Run
// from a standard user shell on a vulnerable build and
// emerge SYSTEM. Pre-flight `CheckVersion` is also
// unprivileged.
//
// # Platform
//
// Windows-only. The TOCTOU lives in
// `AuthzBasepCopyoutInternalSecurityAttributes` —
// Windows kernel exclusive. amd64 / i386 / arm64 all
// affected pre-patch; current implementation targets
// amd64.
//
// # Example
//
// See [ExampleRun] in cve202430088_example_test.go.
//
// # See also
//
//   - docs/techniques/privesc/cve202430088.md
//   - [github.com/oioio-space/maldev/win/version] — `version.CVE202430088()` pre-flight
//   - [github.com/oioio-space/maldev/win/token] — companion token primitives
//
// [github.com/oioio-space/maldev/win/version]: https://pkg.go.dev/github.com/oioio-space/maldev/win/version
// [github.com/oioio-space/maldev/win/token]: https://pkg.go.dev/github.com/oioio-space/maldev/win/token
package cve202430088
