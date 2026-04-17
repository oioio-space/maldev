package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/amsi"
	"github.com/oioio-space/maldev/evasion/etw"
	"github.com/oioio-space/maldev/evasion/unhook"
	"github.com/oioio-space/maldev/inject"
	"github.com/oioio-space/maldev/testutil"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// run dispatches to the selected verification group, prints a single
// READY line with the addresses the orchestrator needs, then sleeps.
func run(group, callerName, resolverName, fn, variant, method string) error {
	fields := map[string]string{
		"pid":    fmt.Sprintf("%d", os.Getpid()),
		"group":  group,
		"caller": callerName,
	}
	switch group {
	case "ssn":
		fields["resolver"] = resolverName
		fields["fn"] = fn
		if err := doSSN(resolverName, fn, fields); err != nil {
			return err
		}
	case "amsi":
		if err := doAMSI(callerName, fields); err != nil {
			return err
		}
	case "etw":
		if err := doETW(callerName, fields); err != nil {
			return err
		}
	case "unhook":
		fields["variant"] = variant
		if err := doUnhook(callerName, variant, fields); err != nil {
			return err
		}
	case "inject":
		fields["method"] = method
		if err := doInject(method, callerName, fields); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown group %q", group)
	}
	fmt.Println(readyLine(fields))
	for {
		time.Sleep(time.Hour)
	}
}

// readyLine serializes fields as "READY k1=v1 k2=v2 ...". Keys are sorted by
// explicit ordering so pid/group/caller come first, rest alphabetical.
func readyLine(f map[string]string) string {
	first := []string{"pid", "group", "caller", "resolver", "variant", "fn"}
	var parts []string
	seen := map[string]bool{}
	for _, k := range first {
		if v, ok := f[k]; ok {
			parts = append(parts, k+"="+v)
			seen[k] = true
		}
	}
	// Collect remaining keys sorted for deterministic output.
	var rest []string
	for k := range f {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sortStrings(rest)
	for _, k := range rest {
		parts = append(parts, k+"="+f[k])
	}
	return "READY " + strings.Join(parts, " ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// -------------------------------------------------------------------
// SSN group

func doSSN(resolverName, fn string, out map[string]string) error {
	r, err := pickResolver(resolverName)
	if err != nil {
		return err
	}
	ssn, err := r.Resolve(fn)
	if err != nil {
		return fmt.Errorf("%s.Resolve(%s): %w", resolverName, fn, err)
	}
	addr, err := localNtdllExport(fn)
	if err != nil {
		return err
	}
	out["ssn"] = fmt.Sprintf("0x%04X", ssn)
	out["addr"] = fmt.Sprintf("0x%x", addr)
	return nil
}

func pickResolver(name string) (wsyscall.SSNResolver, error) {
	switch name {
	case "hellsgate":
		return wsyscall.NewHellsGate(), nil
	case "halosgate":
		return wsyscall.NewHalosGate(), nil
	case "tartarus":
		return wsyscall.NewTartarus(), nil
	case "hashgate":
		return wsyscall.NewHashGate(), nil
	}
	return nil, fmt.Errorf("unknown resolver %q", name)
}

// -------------------------------------------------------------------
// AMSI group

func doAMSI(callerName string, out map[string]string) error {
	caller, err := pickCaller(callerName)
	if err != nil {
		return err
	}
	// Capture AmsiScanBuffer and AmsiOpenSession addresses before patching.
	sbAddr, err := localExport("amsi.dll", "AmsiScanBuffer")
	if err != nil {
		return fmt.Errorf("find AmsiScanBuffer: %w", err)
	}
	osAddr, err := localExport("amsi.dll", "AmsiOpenSession")
	if err != nil {
		return fmt.Errorf("find AmsiOpenSession: %w", err)
	}
	// Scan pre-patch for the JZ (0x74) byte whose offset OpenSession flips.
	flipOffset, err := findJZOffset(osAddr, 1024)
	if err != nil {
		return fmt.Errorf("scan AmsiOpenSession for JZ: %w", err)
	}
	if err := amsi.PatchAll(caller); err != nil {
		return fmt.Errorf("amsi.PatchAll: %w", err)
	}
	out["scanbuffer_addr"] = fmt.Sprintf("0x%x", sbAddr)
	out["opensession_addr"] = fmt.Sprintf("0x%x", osAddr)
	out["opensession_flip_offset"] = fmt.Sprintf("%d", flipOffset)
	return nil
}

// findJZOffset scans up to `limit` bytes from `addr` looking for a JZ (0x74)
// opcode and returns its offset. Mirrors amsi.PatchOpenSession's scan logic
// so the orchestrator knows which byte it needs to re-read post-patch.
func findJZOffset(addr uintptr, limit uintptr) (uintptr, error) {
	for i := uintptr(0); i < limit; i++ {
		b := *(*byte)(unsafe.Pointer(addr + i))
		if b == 0x74 {
			return i, nil
		}
	}
	return 0, fmt.Errorf("JZ (0x74) not found in first %d bytes", limit)
}

// -------------------------------------------------------------------
// ETW group

func doETW(callerName string, out map[string]string) error {
	caller, err := pickCaller(callerName)
	if err != nil {
		return err
	}
	// Capture ntdll ETW addresses BEFORE patching (some may be absent on
	// older Windows versions — emit "0" so the orchestrator knows to skip).
	names := []string{
		"EtwEventWrite", "EtwEventWriteEx", "EtwEventWriteFull",
		"EtwEventWriteString", "EtwEventWriteTransfer", "NtTraceEvent",
	}
	for _, n := range names {
		addr, err := localExport("ntdll.dll", n)
		if err != nil {
			out[strings.ToLower(n)+"_addr"] = "0"
			continue
		}
		out[strings.ToLower(n)+"_addr"] = fmt.Sprintf("0x%x", addr)
	}
	if err := etw.PatchAll(caller); err != nil {
		return fmt.Errorf("etw.PatchAll: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------
// Unhook group

func doUnhook(callerName, variant string, out map[string]string) error {
	caller, err := pickCaller(callerName)
	if err != nil {
		return err
	}
	// Target used for verification: NtCreateSection is the canonical stub
	// referenced in docs/testing.md:133.
	target := "NtCreateSection"
	addr, err := localExport("ntdll.dll", target)
	if err != nil {
		return fmt.Errorf("find %s: %w", target, err)
	}
	out["target"] = target
	out["target_addr"] = fmt.Sprintf("0x%x", addr)
	switch variant {
	case "classic":
		if err := unhook.ClassicUnhook(target, caller); err != nil {
			return fmt.Errorf("ClassicUnhook: %w", err)
		}
	case "full":
		if err := unhook.FullUnhook(caller); err != nil {
			return fmt.Errorf("FullUnhook: %w", err)
		}
	default:
		return fmt.Errorf("unknown unhook variant %q", variant)
	}
	return nil
}

// -------------------------------------------------------------------
// Inject group — self-injects testutil.WindowsSearchableCanary into the
// harness's own address space. The orchestrator attaches to this PID and
// scans for the 16-byte ASCII marker `MALDEV_CANARY!!\n` via /find.

func doInject(methodName, callerName string, out map[string]string) error {
	canary := testutil.WindowsSearchableCanary
	// Marker = last 16 bytes (skip the 3-byte xor eax,eax;ret prologue).
	// Only the marker is used for /find; scanning the prologue would collide
	// with AMSI patches applied earlier in the run.
	marker := canary[3:]
	out["marker_hex"] = hex.EncodeToString(marker)

	switch methodName {
	case "threadpool":
		if err := inject.ThreadPoolExec(canary); err != nil {
			return fmt.Errorf("ThreadPoolExec: %w", err)
		}
	case "sectionmap":
		caller, err := pickCaller(callerName)
		if err != nil {
			return err
		}
		if err := inject.SectionMapInject(os.Getpid(), canary, caller); err != nil {
			return fmt.Errorf("SectionMapInject: %w", err)
		}
	default:
		// Unified injector — CT/CRT/APC/EARLYBIRD/ETWTHR/APCEX/RTL.
		syscallMethod, err := pickWSyscallMethod(callerName)
		if err != nil {
			return err
		}
		cfg := &inject.WindowsConfig{
			Config: inject.Config{
				Method: inject.Method(methodName),
				PID:    os.Getpid(),
			},
			SyscallMethod: syscallMethod,
		}
		inj, err := inject.NewWindowsInjector(cfg)
		if err != nil {
			return fmt.Errorf("NewWindowsInjector: %w", err)
		}
		if err := inj.Inject(canary); err != nil {
			return fmt.Errorf("Inject(%s): %w", methodName, err)
		}
	}
	// Give injected threads/callbacks a moment to execute, then the
	// shellcode region stays RWX-committed in our heap for the orchestrator
	// to scan. No explicit cleanup — the harness process is short-lived.
	time.Sleep(200 * time.Millisecond)
	return nil
}

func pickWSyscallMethod(name string) (wsyscall.Method, error) {
	switch name {
	case "winapi":
		return wsyscall.MethodWinAPI, nil
	case "nativeapi":
		return wsyscall.MethodNativeAPI, nil
	case "direct":
		return wsyscall.MethodDirect, nil
	case "indirect":
		return wsyscall.MethodIndirect, nil
	}
	return 0, fmt.Errorf("unknown caller %q", name)
}

// -------------------------------------------------------------------
// Helpers

// pickCaller maps a CLI name to a live *wsyscall.Caller with HellsGate as
// the default SSN resolver (needed for Direct/Indirect methods; ignored by
// WinAPI/NativeAPI).
func pickCaller(name string) (*wsyscall.Caller, error) {
	var m wsyscall.Method
	switch name {
	case "winapi":
		m = wsyscall.MethodWinAPI
	case "nativeapi":
		m = wsyscall.MethodNativeAPI
	case "direct":
		m = wsyscall.MethodDirect
	case "indirect":
		m = wsyscall.MethodIndirect
	default:
		return nil, fmt.Errorf("unknown caller %q", name)
	}
	return wsyscall.New(m, wsyscall.NewHellsGate()), nil
}

func localNtdllExport(name string) (uintptr, error) {
	return localExport("ntdll.dll", name)
}

func localExport(dll, name string) (uintptr, error) {
	mod, err := windows.LoadLibrary(dll)
	if err != nil {
		return 0, fmt.Errorf("LoadLibrary %s: %w", dll, err)
	}
	addr, err := windows.GetProcAddress(mod, name)
	if err != nil {
		return 0, fmt.Errorf("GetProcAddress %s!%s: %w", dll, name, err)
	}
	return addr, nil
}
