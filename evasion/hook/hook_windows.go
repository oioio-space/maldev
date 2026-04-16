//go:build windows

package hook

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

const (
	jmpRel32Size = 5
	absJmp64Size = 13 // 49 BA imm64 (10) + 41 FF E2 (3)
	maxStealSize = 32
	pageSize     = 4096
)

// Hook represents an installed inline hook on a single function.
type Hook struct {
	target     uintptr
	stealLen   int
	origBytes  []byte
	relay      uintptr
	trampoline uintptr
	mu         sync.Mutex
	installed  bool
}

// Target returns the address of the hooked function.
func (h *Hook) Target() uintptr { return h.target }

// Trampoline returns the address to call the original unhooked function.
func (h *Hook) Trampoline() uintptr { return h.trampoline }

// Install hooks the function at targetAddr, redirecting calls to handler.
// handler must be a Go function whose parameters match the target's
// Windows x64 ABI signature (all uintptr).
func Install(targetAddr uintptr, handler interface{}) (*Hook, error) {
	return install(targetAddr, syscall.NewCallback(handler))
}

// InstallByName resolves a function by DLL and export name, then hooks it.
func InstallByName(dllName, funcName string, handler interface{}) (*Hook, error) {
	proc := windows.NewLazySystemDLL(dllName).NewProc(funcName)
	if err := proc.Find(); err != nil {
		return nil, fmt.Errorf("resolve %s!%s: %w", dllName, funcName, err)
	}
	return Install(proc.Addr(), handler)
}

func install(targetAddr, payloadAddr uintptr) (*Hook, error) {
	var prologueBuf [maxStealSize]byte
	copy(prologueBuf[:], unsafe.Slice((*byte)(unsafe.Pointer(targetAddr)), maxStealSize))

	stealLen, err := calcStealLength(prologueBuf[:], jmpRel32Size)
	if err != nil {
		return nil, fmt.Errorf("analyze prologue: %w", err)
	}

	origBytes := make([]byte, stealLen)
	copy(origBytes, prologueBuf[:stealLen])

	relocs, err := detectRIPRelative(origBytes, stealLen)
	if err != nil {
		return nil, fmt.Errorf("detect RIP-relative: %w", err)
	}

	relay, err := allocateNear(targetAddr, pageSize)
	if err != nil {
		return nil, fmt.Errorf("allocate relay: %w", err)
	}

	trampoline, err := windows.VirtualAlloc(0, uintptr(pageSize),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		windows.VirtualFree(relay, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("allocate trampoline: %w", err)
	}

	// Build trampoline: stolen bytes (with RIP fixups) + absolute JMP back.
	trampolineCode := make([]byte, stealLen+absJmp64Size)
	copy(trampolineCode, origBytes)

	for _, r := range relocs {
		origInstrAddr := targetAddr + uintptr(r.instrOffset)
		origTarget := origInstrAddr + uintptr(r.instrLen) + uintptr(r.origDisp)
		newInstrAddr := trampoline + uintptr(r.instrOffset)
		newDisp := int32(int64(origTarget) - int64(newInstrAddr) - int64(r.instrLen))
		binary.LittleEndian.PutUint32(
			trampolineCode[r.instrOffset+r.dispOffset:],
			uint32(newDisp),
		)
	}

	writeAbsJmp64(trampolineCode[stealLen:], targetAddr+uintptr(stealLen))

	dst := unsafe.Slice((*byte)(unsafe.Pointer(trampoline)), len(trampolineCode))
	copy(dst, trampolineCode)
	var oldProt uint32
	windows.VirtualProtect(trampoline, uintptr(len(trampolineCode)),
		windows.PAGE_EXECUTE_READ, &oldProt)

	// Build relay: absolute JMP to Go callback.
	relayCode := make([]byte, absJmp64Size)
	writeAbsJmp64(relayCode, payloadAddr)
	relayDst := unsafe.Slice((*byte)(unsafe.Pointer(relay)), absJmp64Size)
	copy(relayDst, relayCode)
	windows.VirtualProtect(relay, uintptr(absJmp64Size),
		windows.PAGE_EXECUTE_READ, &oldProt)

	// Patch target: JMP rel32 to relay + NOP padding.
	hookPatch := make([]byte, stealLen)
	writeRelJmp32(hookPatch, targetAddr, relay)
	for i := jmpRel32Size; i < stealLen; i++ {
		hookPatch[i] = 0x90
	}

	if err := api.PatchMemory(targetAddr, hookPatch); err != nil {
		windows.VirtualFree(relay, 0, windows.MEM_RELEASE)
		windows.VirtualFree(trampoline, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("patch target: %w", err)
	}

	flushICache(targetAddr, uintptr(stealLen))

	return &Hook{
		target:     targetAddr,
		stealLen:   stealLen,
		origBytes:  origBytes,
		relay:      relay,
		trampoline: trampoline,
		installed:  true,
	}, nil
}

// Remove unhooks the function, restoring the original prologue bytes
// and freeing the relay and trampoline pages.
func (h *Hook) Remove() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.installed {
		return nil
	}

	if err := api.PatchMemory(h.target, h.origBytes); err != nil {
		return fmt.Errorf("restore original bytes: %w", err)
	}
	flushICache(h.target, uintptr(h.stealLen))

	windows.VirtualFree(h.relay, 0, windows.MEM_RELEASE)
	windows.VirtualFree(h.trampoline, 0, windows.MEM_RELEASE)
	h.installed = false
	return nil
}

func writeAbsJmp64(buf []byte, target uintptr) {
	buf[0] = 0x49
	buf[1] = 0xBA
	binary.LittleEndian.PutUint64(buf[2:], uint64(target))
	buf[10] = 0x41
	buf[11] = 0xFF
	buf[12] = 0xE2
}

func writeRelJmp32(buf []byte, from, to uintptr) {
	buf[0] = 0xE9
	rel := int32(int64(to) - int64(from) - int64(jmpRel32Size))
	binary.LittleEndian.PutUint32(buf[1:], uint32(rel))
}

func allocateNear(target uintptr, size uintptr) (uintptr, error) {
	const maxRange = 0x7FFF0000

	low := target - maxRange
	if low > target {
		low = 0x10000
	}
	high := target + maxRange

	for addr := target &^ (size - 1); addr >= low; addr -= size {
		p, err := windows.VirtualAlloc(addr, size,
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err == nil {
			return p, nil
		}
	}
	for addr := (target + size) &^ (size - 1); addr < high; addr += size {
		p, err := windows.VirtualAlloc(addr, size,
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err == nil {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free page within ±2GB of 0x%X", target)
}

var procFlushInstructionCache = api.Kernel32.NewProc("FlushInstructionCache")

func flushICache(addr, size uintptr) {
	procFlushInstructionCache.Call(
		uintptr(windows.CurrentProcess()),
		addr,
		size,
	)
}
