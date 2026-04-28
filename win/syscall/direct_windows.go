//go:build windows

package syscall

import (
	"fmt"
	"math/rand"
	"sync"
	rawsyscall "syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Call executes a syscall using the configured method.
func (c *Caller) Call(ntFuncName string, args ...uintptr) (uintptr, error) {
	switch c.method {
	case MethodWinAPI:
		return c.callWinAPI(ntFuncName, args...)
	case MethodNativeAPI:
		return c.callNativeAPI(ntFuncName, args...)
	case MethodDirect:
		return c.callDirect(ntFuncName, args...)
	case MethodIndirect:
		return c.callIndirect(ntFuncName, args...)
	case MethodIndirectAsm:
		return c.callIndirectAsm(ntFuncName, args...)
	default:
		return 0, fmt.Errorf("unknown method: %d", c.method)
	}
}

// CallByHash executes a syscall using a pre-computed ROR13 hash instead of
// a function name string. This eliminates plaintext NT function names from
// the binary — the only artifact is a uint32 constant.
//
// For MethodWinAPI/MethodNativeAPI, the function is resolved via PEB walk.
// For MethodDirect/MethodIndirect, the SSN is extracted from the prologue
// found via PEB walk + export hash matching.
//
// Example:
//
//	caller.CallByHash(api.HashNtAllocateVirtualMemory, args...)
func (c *Caller) CallByHash(funcHash uint32, args ...uintptr) (uintptr, error) {
	// Resolve function address via PEB walk — no strings involved.
	ntdllBase, err := pebModuleByHash(hashNtdll)
	if err != nil {
		return 0, fmt.Errorf("PEB walk ntdll: %w", err)
	}
	addr, err := pebExportByHashFunc(ntdllBase, funcHash, c.hashFunc)
	if err != nil {
		return 0, fmt.Errorf("export hash 0x%08X: %w", funcHash, err)
	}

	switch c.method {
	case MethodWinAPI, MethodNativeAPI:
		// Call the resolved address directly via SyscallN.
		r, _, _ := rawsyscall.SyscallN(addr, args...)
		if r != 0 {
			return r, fmt.Errorf("NTSTATUS 0x%08X", uint32(r))
		}
		return 0, nil

	case MethodDirect:
		return c.callDirectAddr(addr, funcHash, args...)
	case MethodIndirect:
		return c.callIndirectAddr(addr, funcHash, args...)
	case MethodIndirectAsm:
		return c.callIndirectAsmAddr(addr, funcHash, args...)
	default:
		return 0, fmt.Errorf("unknown method: %d", c.method)
	}
}

// callDirectAddr builds a direct syscall stub from a pre-resolved function address.
func (c *Caller) callDirectAddr(addr uintptr, funcHash uint32, args ...uintptr) (uintptr, error) {
	b := (*[32]byte)(unsafe.Pointer(addr))
	if b[0] != 0x4C || b[1] != 0x8B || b[2] != 0xD1 || b[3] != 0xB8 {
		return 0, fmt.Errorf("hash 0x%08X: prologue hooked (%02X %02X %02X %02X)", funcHash, b[0], b[1], b[2], b[3])
	}
	ssn := uint16(b[4]) | uint16(b[5])<<8

	stub := []byte{
		0x4C, 0x8B, 0xD1,
		0xB8, byte(ssn), byte(ssn >> 8), 0, 0,
		0x0F, 0x05, 0xC3,
	}
	c.mu.Lock()
	var oldProtect uint32
	copy((*[32]byte)(unsafe.Pointer(c.directStub))[:len(stub)], stub)
	windows.VirtualProtect(c.directStub, 64, windows.PAGE_EXECUTE_READ, &oldProtect)
	r, _, _ := rawsyscall.SyscallN(c.directStub, args...)
	windows.VirtualProtect(c.directStub, 64, windows.PAGE_READWRITE, &oldProtect)
	c.mu.Unlock()
	if r != 0 {
		return r, fmt.Errorf("NTSTATUS 0x%08X", uint32(r))
	}
	return 0, nil
}

// callIndirectAddr builds an indirect syscall stub from a pre-resolved function address.
func (c *Caller) callIndirectAddr(addr uintptr, funcHash uint32, args ...uintptr) (uintptr, error) {
	b := (*[32]byte)(unsafe.Pointer(addr))
	if b[0] != 0x4C || b[1] != 0x8B || b[2] != 0xD1 || b[3] != 0xB8 {
		return 0, fmt.Errorf("hash 0x%08X: prologue hooked (%02X %02X %02X %02X)", funcHash, b[0], b[1], b[2], b[3])
	}
	ssn := uint16(b[4]) | uint16(b[5])<<8

	gadgetAddr, err := pickSyscallGadget()
	if err != nil {
		return 0, fmt.Errorf("find syscall gadget: %w", err)
	}

	stub := make([]byte, 0, 24)
	stub = append(stub, 0x4C, 0x8B, 0xD1)
	stub = append(stub, 0xB8, byte(ssn), byte(ssn>>8), 0, 0)
	stub = append(stub, 0x49, 0xBB)
	for i := 0; i < 8; i++ {
		stub = append(stub, byte(gadgetAddr>>(i*8)))
	}
	stub = append(stub, 0x41, 0xFF, 0xE3)

	c.mu.Lock()
	var oldProtect uint32
	copy((*[32]byte)(unsafe.Pointer(c.indirectStub))[:len(stub)], stub)
	windows.VirtualProtect(c.indirectStub, 64, windows.PAGE_EXECUTE_READ, &oldProtect)
	r, _, _ := rawsyscall.SyscallN(c.indirectStub, args...)
	windows.VirtualProtect(c.indirectStub, 64, windows.PAGE_READWRITE, &oldProtect)
	c.mu.Unlock()
	if r != 0 {
		return r, fmt.Errorf("NTSTATUS 0x%08X", uint32(r))
	}
	return 0, nil
}

func (c *Caller) callWinAPI(name string, args ...uintptr) (uintptr, error) {
	proc := ntdll.NewProc(name)
	if err := proc.Find(); err != nil {
		return 0, err
	}
	r, _, err := proc.Call(args...)
	if r != 0 {
		return r, fmt.Errorf("syscall failed: NTSTATUS 0x%08X: %w", uint32(r), err)
	}
	return 0, nil
}

// callNativeAPI delegates to callWinAPI because NtXxx functions live in
// ntdll.dll — the "native API" IS the Win API layer for these calls.
// The distinction exists so callers can express intent; the implementation
// is identical.
func (c *Caller) callNativeAPI(name string, args ...uintptr) (uintptr, error) {
	return c.callWinAPI(name, args...)
}

func (c *Caller) callDirect(name string, args ...uintptr) (uintptr, error) {
	if c.resolver == nil {
		return 0, fmt.Errorf("direct syscall requires an SSN resolver")
	}
	if c.directStub == 0 {
		return 0, fmt.Errorf("direct stub not allocated (Caller may be closed)")
	}

	ssn, err := c.resolver.Resolve(name)
	if err != nil {
		return 0, fmt.Errorf("resolve SSN: %w", err)
	}

	// Direct syscall stub layout (11 bytes, pre-allocated):
	// 4C 8B D1           mov r10, rcx
	// B8 XX XX 00 00     mov eax, <SSN>
	// 0F 05              syscall
	// C3                 ret
	stub := []byte{
		0x4C, 0x8B, 0xD1, // mov r10, rcx
		0xB8, byte(ssn), byte(ssn >> 8), 0, 0, // mov eax, SSN
		0x0F, 0x05, // syscall
		0xC3, // ret
	}

	// Cycle permissions: RW (write stub) → RX (execute) → RW (ready for next call).
	c.mu.Lock()
	var oldProtect uint32
	copy((*[32]byte)(unsafe.Pointer(c.directStub))[:len(stub)], stub)
	windows.VirtualProtect(c.directStub, 64, windows.PAGE_EXECUTE_READ, &oldProtect)
	r, _, _ := rawsyscall.SyscallN(c.directStub, args...)
	windows.VirtualProtect(c.directStub, 64, windows.PAGE_READWRITE, &oldProtect)
	c.mu.Unlock()

	if r != 0 {
		return r, fmt.Errorf("syscall failed: NTSTATUS 0x%08X", uint32(r))
	}
	return 0, nil
}

func (c *Caller) callIndirect(name string, args ...uintptr) (uintptr, error) {
	if c.resolver == nil {
		return 0, fmt.Errorf("indirect syscall requires an SSN resolver")
	}
	if c.indirectStub == 0 {
		return 0, fmt.Errorf("indirect stub not allocated (Caller may be closed)")
	}

	ssn, err := c.resolver.Resolve(name)
	if err != nil {
		return 0, fmt.Errorf("resolve SSN: %w", err)
	}

	// Find a syscall;ret gadget inside ntdll
	gadgetAddr, err := pickSyscallGadget()
	if err != nil {
		return 0, fmt.Errorf("find syscall gadget: %w", err)
	}

	// Indirect syscall stub layout (21 bytes, pre-allocated):
	// 4C 8B D1              mov r10, rcx
	// B8 XX XX 00 00        mov eax, <SSN>
	// 49 BB <gadget 8B>     mov r11, <gadget address>
	// 41 FF E3              jmp r11
	stub := make([]byte, 0, 24)
	stub = append(stub, 0x4C, 0x8B, 0xD1)                    // mov r10, rcx
	stub = append(stub, 0xB8, byte(ssn), byte(ssn>>8), 0, 0) // mov eax, SSN
	stub = append(stub, 0x49, 0xBB)                           // mov r11, imm64
	for i := 0; i < 8; i++ {
		stub = append(stub, byte(gadgetAddr>>(i*8)))
	}
	stub = append(stub, 0x41, 0xFF, 0xE3) // jmp r11

	// Cycle permissions: RW (write stub) → RX (execute) → RW (ready for next call).
	c.mu.Lock()
	var oldProtect uint32
	copy((*[32]byte)(unsafe.Pointer(c.indirectStub))[:len(stub)], stub)
	windows.VirtualProtect(c.indirectStub, 64, windows.PAGE_EXECUTE_READ, &oldProtect)
	r, _, _ := rawsyscall.SyscallN(c.indirectStub, args...)
	windows.VirtualProtect(c.indirectStub, 64, windows.PAGE_READWRITE, &oldProtect)
	c.mu.Unlock()

	if r != 0 {
		return r, fmt.Errorf("syscall failed: NTSTATUS 0x%08X", uint32(r))
	}
	return 0, nil
}

// callIndirectAsm performs an indirect syscall via the Go-assembly stub —
// no heap stub, no VirtualProtect cycle. The CALL inside the asm stub lands
// on a syscall;ret gadget inside ntdll, so the syscall instruction itself
// executes from a legitimate ntdll page.
func (c *Caller) callIndirectAsm(name string, args ...uintptr) (uintptr, error) {
	ssn, err := c.resolver.Resolve(name)
	if err != nil {
		return 0, fmt.Errorf("resolve SSN: %w", err)
	}
	gadget, err := pickSyscallGadget()
	if err != nil {
		return 0, fmt.Errorf("find syscall gadget: %w", err)
	}
	r := uintptr(indirectSyscallAsm(ssn, gadget, args...))
	if r != 0 {
		return r, fmt.Errorf("syscall failed: NTSTATUS 0x%08X", uint32(r))
	}
	return 0, nil
}

// callIndirectAsmAddr is the CallByHash variant: resolves the SSN from the
// caller-supplied function address (already located by PEB walk + export
// hash), then dispatches via the asm stub.
func (c *Caller) callIndirectAsmAddr(addr uintptr, funcHash uint32, args ...uintptr) (uintptr, error) {
	b := (*[32]byte)(unsafe.Pointer(addr))
	if b[0] != 0x4C || b[1] != 0x8B || b[2] != 0xD1 || b[3] != 0xB8 {
		return 0, fmt.Errorf("hash 0x%08X: prologue hooked (%02X %02X %02X %02X)", funcHash, b[0], b[1], b[2], b[3])
	}
	ssn := uint16(b[4]) | uint16(b[5])<<8
	gadget, err := pickSyscallGadget()
	if err != nil {
		return 0, fmt.Errorf("find syscall gadget: %w", err)
	}
	r := uintptr(indirectSyscallAsm(ssn, gadget, args...))
	if r != 0 {
		return r, fmt.Errorf("NTSTATUS 0x%08X", uint32(r))
	}
	return 0, nil
}

// gadgetPool caches every syscall;ret (0F 05 C3) triple in ntdll's .text
// section. Populated once on first use; subsequent calls draw a random
// element so successive syscalls do not all resolve to the same return
// address (defeats trivial single-address heuristics).
var (
	gadgetPoolOnce sync.Once
	gadgetPool     []uintptr
	gadgetPoolErr  error
)

// pickSyscallGadget returns one syscall;ret gadget address inside ntdll,
// chosen uniformly at random from the cached pool. The pool is enumerated
// lazily on first call (PE section walk over ntdll's .text).
func pickSyscallGadget() (uintptr, error) {
	gadgetPoolOnce.Do(loadGadgetPool)
	if gadgetPoolErr != nil {
		return 0, gadgetPoolErr
	}
	if len(gadgetPool) == 0 {
		return 0, fmt.Errorf("no syscall;ret gadget found in ntdll .text")
	}
	// math/rand is fine here: we only need unpredictability across calls,
	// not cryptographic strength. Auto-seeded by the runtime since 1.20.
	return gadgetPool[rand.Intn(len(gadgetPool))], nil
}

// loadGadgetPool scans ntdll's .text for every `0F 05 C3` triple and
// stores their absolute addresses. Called once via gadgetPoolOnce.
func loadGadgetPool() {
	if err := ntdll.Load(); err != nil {
		gadgetPoolErr = fmt.Errorf("load ntdll: %w", err)
		return
	}
	base := ntdll.Handle()

	dosHeader := (*[2]byte)(unsafe.Pointer(base))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		gadgetPoolErr = fmt.Errorf("invalid MZ header")
		return
	}
	lfanew := *(*int32)(unsafe.Pointer(base + 0x3C))
	peHeader := base + uintptr(lfanew)
	numSections := *(*uint16)(unsafe.Pointer(peHeader + 4 + 2))
	sizeOfOptHdr := *(*uint16)(unsafe.Pointer(peHeader + 4 + 16))
	sectionBase := peHeader + 4 + 20 + uintptr(sizeOfOptHdr)

	for i := uint16(0); i < numSections; i++ {
		secAddr := sectionBase + uintptr(i)*40
		name := (*[8]byte)(unsafe.Pointer(secAddr))
		if string(name[:5]) != ".text" {
			continue
		}
		textVA := *(*uint32)(unsafe.Pointer(secAddr + 12))
		textSize := *(*uint32)(unsafe.Pointer(secAddr + 8))
		textAddr := base + uintptr(textVA)

		for j := uintptr(0); j < uintptr(textSize)-2; j++ {
			b := (*[3]byte)(unsafe.Pointer(textAddr + j))
			if b[0] == 0x0F && b[1] == 0x05 && b[2] == 0xC3 {
				gadgetPool = append(gadgetPool, textAddr+j)
			}
		}
		return
	}
	gadgetPoolErr = fmt.Errorf(".text section not found in ntdll")
}
