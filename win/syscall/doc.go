// Package syscall provides five strategies for invoking Windows NT
// syscalls — from a hookable `kernel32` call to fully indirect SSN
// dispatch through an in-ntdll `syscall;ret` gadget (heap stub or
// Go-assembly stub) — under one uniform [Caller] interface.
//
// The [Caller] type is what every downstream maldev component
// consumes: pass a `*Caller` (or `nil` for the WinAPI default) and
// the call site picks up the operator's chosen evasion posture
// without rewriting business logic. This is the seam the
// `/syscall-methods` matrix testing relies on.
//
// # Methods
//
//   - [MethodWinAPI] — `kernel32!Foo` / `advapi32!Foo`. Fully hookable.
//   - [MethodNativeAPI] — `ntdll!NtFoo`. Bypasses kernel32 hooks but
//     remains hookable at the ntdll boundary.
//   - [MethodDirect] — in-process `syscall` instruction with
//     resolver-supplied SSN. Bypasses all userland hooks.
//   - [MethodIndirect] — jumps into an unmodified `syscall;ret`
//     gadget inside the legitimate ntdll image. Defeats call-stack
//     analysis (return address falls inside ntdll, not the implant).
//     Heap stub is byte-patched and cycled RW↔RX per call.
//   - [MethodIndirectAsm] — same end effect as MethodIndirect, but
//     the SSN+gadget transition lives in a Go-assembly stub: no
//     writable code page in the implant, no per-call VirtualProtect
//     dance, cleaner call stack. amd64 only.
//
// The gadget address used by MethodIndirect / MethodIndirectAsm is
// drawn at random from a pool of every `syscall;ret` triple in
// ntdll's `.text` section, so successive calls do not all return to
// the same ntdll RVA.
//
// # SSN resolvers
//
//   - [HellsGateResolver] — read SSN from the unhooked ntdll
//     stub prologue.
//   - [HalosGateResolver] — when the target stub is hooked, scan
//     neighbouring stubs and offset by stub-index distance.
//   - [TartarusGateResolver] — follow the `JMP` trampoline a hook
//     installs, extract the SSN from the original prologue.
//   - [HashGateResolver] — fully string-free: resolve `Nt*`
//     functions via [github.com/oioio-space/maldev/win/api] PEB walk
//     + ROR13 export hash, then read the SSN. Use [NewHashGateWith]
//     with a custom [HashFunc] (or set one on [Caller.WithHashFunc])
//     to defeat static fingerprinting on well-known ROR13 constants.
//   - [ChainResolver] — try resolvers in sequence; first hit wins.
//
// # MITRE ATT&CK
//
//   - T1106 (Native API)
//   - T1027.007 (Dynamic API Resolution) — Hash/Hell/Halo/Tartarus gates
//
// # Detection level
//
// quiet (Direct) → very-quiet (Indirect)
//
// Direct syscall stubs are detectable by memory scanners: the
// `syscall` instruction inside the implant's image is anomalous.
// Indirect mode pushes the same syscall through ntdll's own
// `syscall;ret` gadget — the call-stack matches a normal NT call
// and the only signal is the SSN value itself.
//
// # Required privileges
//
// unprivileged at the Caller layer. Method selection (WinAPI /
// NativeAPI / Direct / Indirect / IndirectAsm), gadget pool
// build, SSN resolution via PEB walk, and stub byte-patch
// cycle all run in own-process memory at any token.
// Privilege gates only re-emerge inside the syscalls being
// dispatched — `NtOpenProcess(VM_READ)` against lsass.exe
// still needs `SeDebugPrivilege` (admin); the syscall
// transport itself adds none.
//
// # Platform
//
// Windows-only. The package builds without an explicit tag
// because every file underneath is `_windows.go`-suffixed.
// `MethodIndirectAsm` is amd64-only; the other four methods
// support 386 + amd64 + arm64 wherever the SSN table is
// populated. Cross-compile to non-Windows GOOS yields an
// empty build.
//
// # Example
//
// See [ExampleNew] and [ExampleCaller_Call] in syscall_example_test.go.
//
// # See also
//
//   - docs/techniques/syscalls/direct-indirect.md
//   - docs/techniques/syscalls/ssn-resolvers.md
//   - [github.com/oioio-space/maldev/win/api] — companion hash-resolved imports
//   - [github.com/oioio-space/maldev/win/ntapi] — typed wrappers when WinAPI/NativeAPI is enough
//
// [github.com/oioio-space/maldev/win/api]: https://pkg.go.dev/github.com/oioio-space/maldev/win/api
// [github.com/oioio-space/maldev/win/ntapi]: https://pkg.go.dev/github.com/oioio-space/maldev/win/ntapi
package syscall
