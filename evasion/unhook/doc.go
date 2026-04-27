//go:build windows

// Package unhook restores the original prologue bytes of `ntdll.dll`
// functions, removing inline hooks installed by EDR/AV products.
//
// EDRs hook syscall stubs by overwriting the first ~5 bytes of each
// `Nt*` function with a JMP into their monitoring DLL. The original
// stub starts with `4C 8B D1 B8 ?? ?? ?? ??` (`mov r10, rcx; mov eax,
// SSN`). This package restores those bytes from a clean source.
//
// Three escalating strategies:
//
//   - ClassicUnhook(funcName) — read `ntdll.dll` from disk, copy the
//     5-byte prologue back. Has a safelist that rejects Go-runtime-
//     critical functions (NtClose, NtReadFile, …) to avoid deadlocks.
//   - FullUnhook — same disk read but replaces the entire `.text`
//     section in one memcpy. Safe even when the I/O Nt* functions are
//     hooked, because the read completes before any patch is applied.
//   - PerunUnhook — read pristine `ntdll.dll` from a freshly spawned
//     suspended child process (avoids touching disk).
//
// Helpers: DetectHooked walks a list and reports which are hooked;
// IsHooked checks one. CommonHookedFunctions and CommonClassic provide
// a curated default set that EDRs typically watch.
//
// Every entry point accepts a `*wsyscall.Caller` and a
// `stealthopen.Opener`. The Caller routes the patch's
// `NtProtectVirtualMemory` calls through indirect syscalls; the Opener
// (when non-nil) routes the disk read of `ntdll.dll` through
// `OpenFileById` so path-based EDR file hooks can't see it.
//
// # MITRE ATT&CK
//
//   - T1562.001 (Impair Defenses: Disable or Modify Tools)
//
// # Detection level
//
// noisy
//
// EDRs that scan their own hook bytes for tampering catch the restored
// stubs immediately. The disk read of `ntdll.dll` is itself
// instrumentable. PerunUnhook (process-spawn variant) leaves the
// suspended-child-process artefact.
//
// # Example
//
// See [ExampleClassic] and [ExampleFull] in unhook_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/ntdll-unhooking.md
//   - [github.com/oioio-space/maldev/evasion/stealthopen] — `Opener` for the disk read
//   - [github.com/oioio-space/maldev/win/syscall] — Caller chain
//
// [github.com/oioio-space/maldev/evasion/stealthopen]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/stealthopen
// [github.com/oioio-space/maldev/win/syscall]: https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall
package unhook
