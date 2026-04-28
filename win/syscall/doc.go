// Package syscall provides four strategies for invoking Windows NT
// syscalls — from a hookable `kernel32` call to fully indirect SSN
// dispatch through an in-ntdll `syscall;ret` gadget — under one
// uniform [Caller] interface.
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
//     + ROR13 export hash, then read the SSN.
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
