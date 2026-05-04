// Package herpaderping implements Process Herpaderping and the
// related Process Ghosting variant — kernel image-section cache
// exploitation that lets the running process execute one PE
// while the file on disk reads as another (or doesn't exist).
//
// The kernel's image-section cache is the lever. When a process
// is created the sequence is:
//
//  1. NtCreateSection(SEC_IMAGE) — kernel maps + caches the PE
//     image into an immutable section object, persistently.
//  2. NtCreateProcessEx — process object created from the
//     section; no threads yet.
//  3. File overwrite (Herpaderping) or file delete (Ghosting) —
//     the on-disk file is replaced with a decoy or unlinked.
//  4. NtCreateThreadEx — initial thread created. EDR / AV
//     security callbacks fire here; any file read returns the
//     decoy / fails open.
//
// The running process executes the original payload from the
// kernel image cache. File-based inspection — EDR, Task Manager,
// forensic tools — sees only the decoy.
//
// Comparison with related techniques:
//
//   - Process Hollowing (T1055.012) — writes shellcode into a
//     suspended process via WriteProcessMemory. The on-disk
//     image of the *host* process is never modified. Memory
//     forensics still recovers the injection. Herpaderping
//     operates at a lower level (kernel cache) — the deception
//     is in the kernel, not user-space memory.
//   - Process Ghosting ([ModeGhosting], Gabriel Landau 2021) —
//     creates a delete-pending file, maps as SEC_IMAGE, closes
//     the handle to let deletion complete BEFORE creating the
//     process. The file never exists at thread-creation time.
//     Both modes exploit the same kernel primitive at different
//     lifecycle stages.
//
// Win11 26100+ (24H2 / 25H2) hardens NtCreateProcessEx against
// section-from-tampered-or-deleted-file. Both [ModeHerpaderping]
// and [ModeGhosting] return STATUS_NOT_SUPPORTED on those
// builds — the package treats every Win11 build ≥ 26100 as
// "blocked" out of caution. Operators with verified-working
// 26100 builds can drop the test skip locally; new bypass
// research is required for 26100+ targets.
//
// References:
//
//   - Original Herpaderping research: https://jxy-s.github.io/herpaderping/
//   - Ghosting (Gabriel Landau, 2021): https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack
//
// # MITRE ATT&CK
//
//   - T1055.013 (Process Doppelgänging) — closest sibling family
//   - T1055 (Process Injection) — defense evasion via process tampering
//   - T1027.005 (Indicator Removal from Tools) — file-on-disk decoy defeats authenticode-of-disk-image checks
//
// # Detection level
//
// moderate
//
// Sysmon Event ID 25 (ProcessTampering) is the primary
// detection signal — the kernel detects mapped-image vs
// disk-image divergence and emits the event. Advanced EDRs
// also watch for `NtCreateSection(SEC_IMAGE)` followed by a
// file write on the same handle before `NtCreateThreadEx`,
// and for processes whose authenticode chain resolves to a
// decoy PE while memory layout matches a different
// executable.
//
// # Required privileges
//
// unprivileged. The technique only manipulates files +
// kernel objects the calling user already owns —
// `NtCreateSection(SEC_IMAGE)` against a writable file in
// the operator's own scratch dir, then file overwrite /
// delete via standard Win32 file APIs. No
// `SeDebugPrivilege`, no admin. The on-disk decoy / ghost
// destination only needs the caller's write permission,
// typically `%TEMP%` or any user-writable path.
//
// # Platform
//
// Windows-only. Kernel image-section cache + Sysmon Event 25
// detection are Windows-specific kernel surfaces; no POSIX
// equivalent. Effective only on Win11 < 26100 — newer builds
// reject the section-from-tampered-file path with
// STATUS_NOT_SUPPORTED (see Limitations + the version-gating
// in `Run`).
//
// # Example
//
// See [ExampleRun] in herpaderping_example_test.go.
//
// # See also
//
//   - docs/techniques/process/herpaderping.md
//   - [github.com/oioio-space/maldev/inject] — alternative to herpaderping for in-process delivery
//   - [github.com/oioio-space/maldev/evasion] — pair with AMSI/ETW patches for the spawned process
//
// [github.com/oioio-space/maldev/inject]: https://pkg.go.dev/github.com/oioio-space/maldev/inject
// [github.com/oioio-space/maldev/evasion]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion
package herpaderping
