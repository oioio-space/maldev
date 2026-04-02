//go:build windows

package syscall

import (
	"fmt"
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
	default:
		return 0, fmt.Errorf("unknown method: %d", c.method)
	}
}

func (c *Caller) callWinAPI(name string, args ...uintptr) (uintptr, error) {
	proc := ntdll.NewProc(name)
	if err := proc.Find(); err != nil {
		return 0, err
	}
	r, _, err := proc.Call(args...)
	if r != 0 {
		return r, fmt.Errorf("%s: NTSTATUS 0x%08X: %w", name, uint32(r), err)
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

	ssn, err := c.resolver.Resolve(name)
	if err != nil {
		return 0, fmt.Errorf("resolve SSN for %s: %w", name, err)
	}

	// Build the direct syscall stub in executable memory:
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

	// Allocate executable memory for the stub
	stubAddr, err := windows.VirtualAlloc(0, uintptr(len(stub)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, fmt.Errorf("VirtualAlloc stub: %w", err)
	}
	defer windows.VirtualFree(stubAddr, 0, windows.MEM_RELEASE)

	// Copy stub into executable memory
	copy((*[32]byte)(unsafe.Pointer(stubAddr))[:len(stub)], stub)

	// Call the stub via syscall.SyscallN
	r, _, _ := rawsyscall.SyscallN(stubAddr, args...)
	if r != 0 {
		return r, fmt.Errorf("%s: NTSTATUS 0x%08X", name, uint32(r))
	}
	return 0, nil
}

func (c *Caller) callIndirect(name string, args ...uintptr) (uintptr, error) {
	if c.resolver == nil {
		return 0, fmt.Errorf("indirect syscall requires an SSN resolver")
	}

	ssn, err := c.resolver.Resolve(name)
	if err != nil {
		return 0, fmt.Errorf("resolve SSN for %s: %w", name, err)
	}

	// Find a syscall;ret gadget inside ntdll
	gadgetAddr, err := findSyscallGadget()
	if err != nil {
		return 0, fmt.Errorf("find syscall gadget: %w", err)
	}

	// Build the indirect syscall stub:
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

	stubAddr, err := windows.VirtualAlloc(0, uintptr(len(stub)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, fmt.Errorf("VirtualAlloc stub: %w", err)
	}
	defer windows.VirtualFree(stubAddr, 0, windows.MEM_RELEASE)

	copy((*[32]byte)(unsafe.Pointer(stubAddr))[:len(stub)], stub)

	r, _, _ := rawsyscall.SyscallN(stubAddr, args...)
	if r != 0 {
		return r, fmt.Errorf("%s: NTSTATUS 0x%08X", name, uint32(r))
	}
	return 0, nil
}

// findSyscallGadget scans ntdll's .text section for a syscall;ret (0F 05 C3) gadget.
func findSyscallGadget() (uintptr, error) {
	// Force-load ntdll via the shared package-local LazyDLL to get the base address
	// for raw PE section parsing.
	if err := ntdll.Load(); err != nil {
		return 0, fmt.Errorf("load ntdll: %w", err)
	}
	base := ntdll.Handle()

	// Parse PE headers to find .text section
	dosHeader := (*[2]byte)(unsafe.Pointer(base))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return 0, fmt.Errorf("invalid MZ header")
	}
	lfanew := *(*int32)(unsafe.Pointer(base + 0x3C))
	peHeader := base + uintptr(lfanew)
	numSections := *(*uint16)(unsafe.Pointer(peHeader + 4 + 2))
	sizeOfOptHdr := *(*uint16)(unsafe.Pointer(peHeader + 4 + 16))
	sectionBase := peHeader + 4 + 20 + uintptr(sizeOfOptHdr)

	for i := uint16(0); i < numSections; i++ {
		secAddr := sectionBase + uintptr(i)*40
		name := (*[8]byte)(unsafe.Pointer(secAddr))
		if string(name[:5]) == ".text" {
			textVA := *(*uint32)(unsafe.Pointer(secAddr + 12))
			textSize := *(*uint32)(unsafe.Pointer(secAddr + 8))
			textAddr := base + uintptr(textVA)

			// Scan for syscall;ret gadget: 0F 05 C3
			for j := uintptr(0); j < uintptr(textSize)-2; j++ {
				b := (*[3]byte)(unsafe.Pointer(textAddr + j))
				if b[0] == 0x0F && b[1] == 0x05 && b[2] == 0xC3 {
					return textAddr + j, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("no syscall;ret gadget found in ntdll .text")
}
