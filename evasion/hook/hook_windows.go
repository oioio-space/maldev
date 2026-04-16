//go:build windows

package hook

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/unhook"
	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

const (
	jmpRel32Size = 5
	absJmp64Size = 13 // 49 BA imm64 (10) + 41 FF E2 (3)
	maxStealSize = 32
	pageSize     = 4096
	memFree      = 0x10000
)

// Hook represents an installed inline hook on a single function.
type Hook struct {
	target     uintptr
	stealLen   int
	origBytes  []byte
	relay      uintptr
	trampoline uintptr
	caller     *wsyscall.Caller
	mu         sync.Mutex
	installed  bool
}

// HookOption configures hook installation behaviour.
type HookOption func(*hookConfig)

type hookConfig struct {
	caller     *wsyscall.Caller
	cleanFirst bool
}

// WithCaller routes the memory-patch syscall through the given Caller,
// enabling indirect or direct syscall dispatch for EDR evasion.
func WithCaller(c *wsyscall.Caller) HookOption {
	return func(cfg *hookConfig) { cfg.caller = c }
}

// WithCleanFirst re-reads the target function from disk before installing
// the hook, removing any EDR hooks that may already be present.
func WithCleanFirst() HookOption {
	return func(cfg *hookConfig) { cfg.cleanFirst = true }
}

// Target returns the address of the hooked function.
func (h *Hook) Target() uintptr { return h.target }

// Trampoline returns the address to call the original unhooked function.
func (h *Hook) Trampoline() uintptr { return h.trampoline }

// Install hooks the function at targetAddr, redirecting calls to handler.
// handler must be a Go function whose parameters match the target's
// Windows x64 ABI signature (all uintptr).
func Install(targetAddr uintptr, handler interface{}, opts ...HookOption) (*Hook, error) {
	if reflect.TypeOf(handler).Kind() != reflect.Func {
		return nil, fmt.Errorf("handler must be a func, got %T", handler)
	}
	cfg := &hookConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return install(targetAddr, syscall.NewCallback(handler), cfg)
}

// InstallByName resolves a function by DLL and export name, then hooks it.
func InstallByName(dllName, funcName string, handler interface{}, opts ...HookOption) (*Hook, error) {
	proc := windows.NewLazySystemDLL(dllName).NewProc(funcName)
	if err := proc.Find(); err != nil {
		return nil, fmt.Errorf("resolve %s!%s: %w", dllName, funcName, err)
	}
	cfg := &hookConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.cleanFirst {
		unhook.ClassicUnhook(funcName, cfg.caller)
	}
	return install(proc.Addr(), syscall.NewCallback(handler), cfg)
}

func install(targetAddr, payloadAddr uintptr, cfg *hookConfig) (*Hook, error) {
	var prologueBuf [maxStealSize]byte
	copy(prologueBuf[:], unsafe.Slice((*byte)(unsafe.Pointer(targetAddr)), maxStealSize))

	stealLen, relocs, err := analyzePrologue(prologueBuf[:], jmpRel32Size)
	if err != nil {
		return nil, fmt.Errorf("analyze prologue: %w", err)
	}

	origBytes := make([]byte, stealLen)
	copy(origBytes, prologueBuf[:stealLen])

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

	// Write trampoline directly into mapped page: stolen bytes + JMP back.
	trampolineDst := unsafe.Slice((*byte)(unsafe.Pointer(trampoline)), stealLen+absJmp64Size)
	copy(trampolineDst, origBytes)

	for _, r := range relocs {
		origInstrAddr := targetAddr + uintptr(r.instrOffset)
		origTarget := origInstrAddr + uintptr(r.instrLen) + uintptr(r.origDisp)
		newInstrAddr := trampoline + uintptr(r.instrOffset)
		newDisp := int32(int64(origTarget) - int64(newInstrAddr) - int64(r.instrLen))
		binary.LittleEndian.PutUint32(
			trampolineDst[r.instrOffset+r.dispOffset:],
			uint32(newDisp),
		)
	}

	writeAbsJmp64(trampolineDst[stealLen:], targetAddr+uintptr(stealLen))

	var oldProt uint32
	if err := windows.VirtualProtect(trampoline, uintptr(len(trampolineDst)),
		windows.PAGE_EXECUTE_READ, &oldProt); err != nil {
		windows.VirtualFree(relay, 0, windows.MEM_RELEASE)
		windows.VirtualFree(trampoline, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("protect trampoline: %w", err)
	}

	// Write relay directly into mapped page: absolute JMP to Go callback.
	relayDst := unsafe.Slice((*byte)(unsafe.Pointer(relay)), absJmp64Size)
	writeAbsJmp64(relayDst, payloadAddr)

	if err := windows.VirtualProtect(relay, uintptr(absJmp64Size),
		windows.PAGE_EXECUTE_READ, &oldProt); err != nil {
		windows.VirtualFree(relay, 0, windows.MEM_RELEASE)
		windows.VirtualFree(trampoline, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("protect relay: %w", err)
	}

	hookPatch := make([]byte, stealLen)
	writeRelJmp32(hookPatch, targetAddr, relay)
	for i := jmpRel32Size; i < stealLen; i++ {
		hookPatch[i] = 0x90
	}

	if cfg.caller != nil {
		err = api.PatchMemoryWithCaller(targetAddr, hookPatch, cfg.caller)
	} else {
		err = api.PatchMemory(targetAddr, hookPatch)
	}
	if err != nil {
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
		caller:     cfg.caller,
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

	var err error
	if h.caller != nil {
		err = api.PatchMemoryWithCaller(h.target, h.origBytes, h.caller)
	} else {
		err = api.PatchMemory(h.target, h.origBytes)
	}
	if err != nil {
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
	if high < target {
		high = ^uintptr(0)
	}

	var mbi windows.MemoryBasicInformation
	mbiSize := unsafe.Sizeof(mbi)

	// Scan downward.
	for addr := target &^ (size - 1); addr >= low; {
		if err := windows.VirtualQuery(addr, &mbi, mbiSize); err != nil {
			break
		}
		if mbi.State == memFree && mbi.RegionSize >= size {
			p, err := windows.VirtualAlloc(addr, size,
				windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
			if err == nil {
				return p, nil
			}
		}
		if mbi.AllocationBase == 0 || uintptr(mbi.AllocationBase) >= addr {
			break
		}
		addr = uintptr(mbi.AllocationBase) - size
	}

	// Scan upward.
	for addr := (target + size) &^ (size - 1); addr < high; {
		if err := windows.VirtualQuery(addr, &mbi, mbiSize); err != nil {
			break
		}
		if mbi.State == memFree && mbi.RegionSize >= size {
			p, err := windows.VirtualAlloc(addr, size,
				windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
			if err == nil {
				return p, nil
			}
		}
		addr = mbi.BaseAddress + mbi.RegionSize
	}

	return 0, fmt.Errorf("no free page within ±2GB of 0x%X", target)
}

func flushICache(addr, size uintptr) {
	api.ProcFlushInstructionCache.Call(
		uintptr(windows.CurrentProcess()),
		addr,
		size,
	)
}
