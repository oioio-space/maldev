// Package inject provides unified shellcode injection across Windows
// and Linux with a fluent builder, decorator middleware, and automatic
// fallback between methods.
//
// Sixteen Windows methods cover every common shape: classic remote
// thread (CreateRemoteThread, RtlCreateUserThread), self-injection
// (CreateThread, CreateFiber, EtwpCreateEtwThread), child-process
// hijacks (EarlyBird APC, Thread Hijack on a CREATE_SUSPENDED child),
// callback abuse (EnumWindows, CreateTimerQueueTimer,
// CertEnumSystemStore), thread-pool work items (TpAllocWork +
// TpPostWork), kernel callback table hijack via PEB, phantom DLL
// (map clean System32 section then overwrite .text), section mapping
// (NtCreateSection + NtMapViewOfSection cross-process), command-line
// argument spoofing (PEB rewrite after CREATE_SUSPENDED), and the
// special-case NtQueueApcThreadEx that does not need an alertable
// wait. Three Linux methods (ptrace attach, memfd_create, /proc/pid/mem)
// plus a CGo-free purego path round out the cross-platform surface.
//
// Every method implements [Injector]. Self-process methods additionally
// implement [SelfInjector] so callers can pass the freshly allocated
// region into evasion/sleepmask or cleanup/memory.WipeAndFree without
// re-deriving address and size. Decorators (WithValidation, WithCPUDelay,
// WithXOR) and the [Pipeline] forward [InjectedRegion] transparently,
// so the pattern works at the end of any chain. The [InjectorBuilder]
// returned by [Build] selects syscall mode (WinAPI / NativeAPI / direct
// / indirect with arbitrary [wsyscall.SSNResolver]), pins the target,
// stacks middleware, and emits an [Injector].
//
// # MITRE ATT&CK
//
//   - T1055 (Process Injection)
//   - T1055.001 (DLL Injection) — CreateRemoteThread variants
//   - T1055.003 (Thread Execution Hijacking) — ThreadHijack
//   - T1055.004 (Asynchronous Procedure Call) — APC, EarlyBird APC, NtQueueApcThreadEx
//   - T1055.012 (Process Hollowing) — adjacent; the package keeps the
//     legacy MethodProcessHollowing alias pointing at MethodThreadHijack
//   - T1055.015 (ListPlanting) — CreateTimerQueueTimer / EnumWindows callback paths
//
// # Detection level
//
// noisy
//
// Process injection is the single most-monitored class of malicious
// behaviour on Windows. EDR vendors hook every kernel32, ntdll, and
// kernel callback path that this package can travel. Per-method detail
// lives in docs/techniques/injection/<method>.md.
//
// # Example
//
// See [ExampleNewWindowsInjector], [ExampleBuild], and [ExamplePipeline]
// in inject_example_test.go.
//
// # See also
//
//   - docs/techniques/injection/README.md
//   - [github.com/oioio-space/maldev/win/syscall] — Caller and SSN resolvers
//   - [github.com/oioio-space/maldev/evasion/sleepmask] — pair with [SelfInjector] to mask the region during sleep
//   - [github.com/oioio-space/maldev/cleanup/memory] — pair with [SelfInjector] to wipe the region on exit
//
// [github.com/oioio-space/maldev/win/syscall]: https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall
// [github.com/oioio-space/maldev/evasion/sleepmask]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/sleepmask
// [github.com/oioio-space/maldev/cleanup/memory]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/memory
package inject
