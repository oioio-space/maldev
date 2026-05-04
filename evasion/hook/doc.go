//go:build windows

// Package hook installs x64 inline hooks on exported Windows functions:
// patch the prologue with a JMP to a Go callback, automatically generate
// a trampoline for calling the original, and fix up RIP-relative
// instructions in the stolen prologue.
//
// Hook represents a single installed hook; HookGroup batches several
// for atomic install/remove. Functional options (`HookOption`) tune
// install behaviour: probe-only mode, remote-process install, IPC
// bridge controller for out-of-process callbacks. GoHandler /
// GoHandlerBytes generate self-contained shellcode that runs an
// arbitrary Go DLL handler without CGo. RemoteInstall /
// RemoteInstallByName install hooks in a target process via
// `CreateRemoteThread`-class injection.
//
// No CGo required — uses `syscall.NewCallback` for the Go-to-native
// bridge. No external disassembler — prologue analysis uses
// `golang.org/x/arch/x86asm`.
//
// # MITRE ATT&CK
//
//   - T1574.012 (Hijack Execution Flow: COR_PROFILER —
//     inline-hook scaffolding falls under the same parent technique)
//
// # Detection level
//
// noisy
//
// EDR integrity checks detect modified function prologues. Cross-
// process install path triggers `EVENT_TI_NTPROTECT` on the target's
// loaded modules.
//
// # Required privileges
//
// In-process `Install` is unprivileged — RW flip + JMP
// patch on the calling process's own pages. `RemoteInstall`
// / `RemoteInstallByName` need a handle to the target with
// `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`:
// same-user same-IL is unprivileged; cross-user / protected
// targets need `SeDebugPrivilege` (admin).
//
// # Platform
//
// Windows-only (`//go:build windows`) and amd64-only —
// the prologue analyser uses x86asm and the JMP relay
// assumes x64 register layout. Win11 26100+ may interact
// with CET — see `evasion/cet` for the ENDBR64 prefix
// helper.
//
// # Example
//
// See [ExampleNew] and [ExampleInstallByName] in hook_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/inline-hook.md
//   - [github.com/oioio-space/maldev/evasion/hook/bridge] — IPC controller
//   - [github.com/oioio-space/maldev/evasion/hook/shellcode] — trampoline generator
//
// [github.com/oioio-space/maldev/evasion/hook/bridge]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/bridge
// [github.com/oioio-space/maldev/evasion/hook/shellcode]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/shellcode
package hook
