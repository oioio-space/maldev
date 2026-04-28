// Package shellcode ships pre-fabricated x64 position-independent
// shellcode blobs used as handler bodies for
// [github.com/oioio-space/maldev/evasion/hook].`RemoteInstall`. The
// blobs run inside the target process when the hooked function is
// called and override its return value without invoking the
// trampoline.
//
// Each generator returns a `[]byte` blob that is RIP-relative,
// has no imports, and patches its own immediate operands at install
// time. The implant injects the blob into the target's address
// space, points a hook at it, and the next call to the hooked
// function lands inside the shellcode instead of the original body.
//
// Available blobs:
//
//   - [Block] — `XOR RAX, RAX; RET`. Returns 0 / FALSE / NULL —
//     defeats AV-style scanner returns (`AmsiScanBuffer`,
//     `IsDebuggerPresent`).
//   - [ReturnTrue] — `MOV RAX, 1; RET`. Returns 1 / TRUE — flips a
//     boolean check (`AmsiInitialize`-style success).
//   - [Custom] — caller-supplied bytes; helper for one-off payloads
//     when the canned variants don't fit.
//
// # MITRE ATT&CK
//
//   - T1574.012 (Hijack Execution Flow: Inline Hooking) — handler payload
//   - T1027 (Obfuscated Files or Information) — shellcode is implicit obfuscation
//
// # Detection level
//
// noisy
//
// EDRs that scan RX pages for syscall-style patterns flag canned
// shellcode prologues. The blobs are intentionally tiny (≤ 8 bytes)
// to slip under heuristics, but pair with
// [github.com/oioio-space/maldev/evasion/sleepmask] to encrypt the
// blob between callbacks for hardened targets.
//
// # Example
//
// See [ExampleBlock] in shellcode_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/inline-hook.md
//   - [github.com/oioio-space/maldev/evasion/hook] — the install
//     primitive that consumes these blobs
//   - [github.com/oioio-space/maldev/inject] — alternative path when
//     the goal is full shellcode execution rather than hook payload
//
// [github.com/oioio-space/maldev/evasion/hook]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook
// [github.com/oioio-space/maldev/inject]: https://pkg.go.dev/github.com/oioio-space/maldev/inject
package shellcode
