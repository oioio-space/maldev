//go:build windows

package syscall

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ntdll is a package-local handle to avoid an import cycle with win/api.
var ntdll = windows.NewLazySystemDLL("ntdll.dll")

// SSNResolver resolves the Syscall Service Number (SSN) for an NT function.
type SSNResolver interface {
	Resolve(ntFuncName string) (uint16, error)
}

// HellsGateResolver reads the SSN directly from the ntdll function prologue.
// Fails if the function is hooked (bytes modified by EDR).
type HellsGateResolver struct{}

func NewHellsGate() *HellsGateResolver { return &HellsGateResolver{} }

func (r *HellsGateResolver) Resolve(name string) (uint16, error) {
	proc := ntdll.NewProc(name)
	if err := proc.Find(); err != nil {
		return 0, fmt.Errorf("find %s: %w", name, err)
	}
	addr := proc.Addr()

	// Standard ntdll x64 prologue: 4C 8B D1 B8 XX XX 00 00
	// mov r10, rcx; mov eax, <SSN>
	b := (*[32]byte)(unsafe.Pointer(addr))

	// Check for standard prologue
	if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
		ssn := uint16(b[4]) | uint16(b[5])<<8
		return ssn, nil
	}

	return 0, fmt.Errorf("%s: prologue hooked or unrecognized (first bytes: %02X %02X %02X %02X)", name, b[0], b[1], b[2], b[3])
}

// HalosGateResolver extends Hell's Gate by scanning neighboring functions
// when the target is hooked. Since SSNs are sequential, if a nearby
// function N is unhooked and has SSN=X, the target SSN = X +/- offset.
type HalosGateResolver struct{}

func NewHalosGate() *HalosGateResolver { return &HalosGateResolver{} }

func (r *HalosGateResolver) Resolve(name string) (uint16, error) {
	// Try Hell's Gate first
	hg := NewHellsGate()
	ssn, err := hg.Resolve(name)
	if err == nil {
		return ssn, nil
	}

	proc := ntdll.NewProc(name)
	if err := proc.Find(); err != nil {
		return 0, fmt.Errorf("find %s: %w", name, err)
	}
	addr := proc.Addr()

	// Scan neighboring functions (each syscall stub is 32 bytes on x64)
	const stubSize = 32
	for offset := 1; offset <= 500; offset++ {
		// Check function above
		upAddr := addr - uintptr(offset*stubSize)
		b := (*[8]byte)(unsafe.Pointer(upAddr))
		if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
			neighborSSN := uint16(b[4]) | uint16(b[5])<<8
			return neighborSSN + uint16(offset), nil
		}

		// Check function below
		downAddr := addr + uintptr(offset*stubSize)
		b = (*[8]byte)(unsafe.Pointer(downAddr))
		if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
			neighborSSN := uint16(b[4]) | uint16(b[5])<<8
			if uint16(offset) > neighborSSN {
				continue
			}
			return neighborSSN - uint16(offset), nil
		}
	}

	return 0, fmt.Errorf("%s: no unhooked neighbor found within 500 stubs", name)
}

// TartarusGateResolver extends Halo's Gate by recognizing JMP-hooked
// functions (E9/EB patches injected by EDR) and following the hook
// displacement to extract the original SSN from the trampoline code.
// Falls back to Halo's Gate neighbor scanning if the trampoline does not
// contain a recognizable mov eax, <SSN> instruction.
type TartarusGateResolver struct{}

func NewTartarus() *TartarusGateResolver { return &TartarusGateResolver{} }

func (r *TartarusGateResolver) Resolve(name string) (uint16, error) {
	proc := ntdll.NewProc(name)
	if err := proc.Find(); err != nil {
		return 0, fmt.Errorf("find %s: %w", name, err)
	}
	addr := proc.Addr()
	b := (*[32]byte)(unsafe.Pointer(addr))

	// Check for standard (unhooked) prologue: mov r10,rcx; mov eax,<SSN>
	if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
		return uint16(b[4]) | uint16(b[5])<<8, nil
	}

	// Check for near JMP hook (E9 XX XX XX XX — rel32 displacement)
	if b[0] == 0xE9 {
		displacement := *(*int32)(unsafe.Pointer(&b[1]))
		hookDest := addr + 5 + uintptr(displacement)
		destBytes := (*[64]byte)(unsafe.Pointer(hookDest))
		for i := 0; i < 60; i++ {
			if destBytes[i] == 0xB8 { // mov eax, imm32
				ssn := uint16(destBytes[i+1]) | uint16(destBytes[i+2])<<8
				return ssn, nil
			}
		}
	}

	// Check for short JMP hook (EB XX — rel8 displacement)
	if b[0] == 0xEB {
		displacement := int8(b[1])
		hookDest := addr + 2 + uintptr(displacement)
		destBytes := (*[64]byte)(unsafe.Pointer(hookDest))
		for i := 0; i < 60; i++ {
			if destBytes[i] == 0xB8 {
				ssn := uint16(destBytes[i+1]) | uint16(destBytes[i+2])<<8
				return ssn, nil
			}
		}
	}

	// Fall back to Halo's Gate neighbor scanning
	hg := NewHalosGate()
	return hg.Resolve(name)
}

// ChainResolver tries multiple resolvers in sequence, returning the first success.
type ChainResolver struct {
	resolvers []SSNResolver
}

func Chain(resolvers ...SSNResolver) *ChainResolver {
	return &ChainResolver{resolvers: resolvers}
}

func (c *ChainResolver) Resolve(name string) (uint16, error) {
	var lastErr error
	for _, r := range c.resolvers {
		ssn, err := r.Resolve(name)
		if err == nil {
			return ssn, nil
		}
		lastErr = err
	}
	return 0, fmt.Errorf("all resolvers failed for %s: %w", name, lastErr)
}
