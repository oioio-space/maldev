//go:build windows

// syscall-matrix — panorama 17 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/syscalls/README.md          — three orthogonal axes,
//                                                   "downstream packages
//                                                   accept a *Caller and
//                                                   inherit the chosen
//                                                   posture without
//                                                   recompiling"
//   - docs/techniques/syscalls/ssn-resolvers.md   — 4 resolvers + Chain,
//                                                   "Combined Example:
//                                                   Resolver Resilience
//                                                   Test" (lines 286-324)
//   - docs/techniques/syscalls/direct-indirect.md — 5 calling methods
//   - docs/techniques/evasion/amsi-bypass.md      — amsi.PatchScanBuffer
//                                                   accepts *Caller
//   - docs/techniques/evasion/etw-patching.md     — etw.PatchAll accepts
//                                                   *Caller
//
// The composability claim ("inherit the posture without recompiling") is
// what we audit here. Earlier panoramas pinned a single Caller; this one
// sweeps the 5 methods × 4 resolvers grid to surface any cell where the
// doc-promised wiring drifts from reality.
package main

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion/amsi"
	"github.com/oioio-space/maldev/evasion/etw"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

type namedResolver struct {
	name string
	r    wsyscall.SSNResolver
}

func main() {
	// Resolvers are reused across cells: HellsGate/Tartarus/HashGate cache
	// SSNs internally, so rebuilding them per cell would defeat the cache
	// and rewalk ntdll on every call.
	resolvers := []namedResolver{
		{"HellsGate", wsyscall.NewHellsGate()},
		{"HalosGate", wsyscall.NewHalosGate()},
		{"TartarusGate", wsyscall.NewTartarus()},
		{"HashGate", wsyscall.NewHashGate()},
	}

	// 1. Resolver matrix — verbatim from ssn-resolvers.md "Combined Example"
	//    (lines 286-324). Surfaces resolver-only failures before any caller
	//    machinery is involved.
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

	// 2. Method × Resolver matrix — exercises the actual call path. NtClose
	//    on a sentinel handle (0xDEAD) is the same probe used in
	//    win/syscall/syscall_test.go: it must reach the kernel and come
	//    back with STATUS_INVALID_HANDLE, regardless of method/resolver.
	methods := []wsyscall.Method{
		wsyscall.MethodWinAPI,
		wsyscall.MethodNativeAPI,
		wsyscall.MethodDirect,
		wsyscall.MethodIndirect,
		wsyscall.MethodIndirectAsm,
	}
	fmt.Println("\n=== Caller matrix (5 methods x 4 resolvers, NtClose 0xDEAD) ===")
	for _, m := range methods {
		for _, nr := range resolvers {
			runCell(fmt.Sprintf("%s/%s", m, nr.name), m, nr.r)
		}
	}

	// 3. Chain composability — ssn-resolvers.md line 247 promises
	//    `Chain(Tartarus, HashGate, HalosGate)` as the doc-canonical
	//    resilient chain. Run it through every method.
	chain := wsyscall.Chain(
		wsyscall.NewTartarus(),
		wsyscall.NewHashGate(),
		wsyscall.NewHalosGate(),
	)
	fmt.Println("\n=== Chain(Tartarus, HashGate, HalosGate) x 5 methods ===")
	for _, m := range methods {
		runCell(fmt.Sprintf("%s/Chain", m), m, chain)
	}

	// 4. Consumer composability — verifies the README.md claim that
	//    "downstream packages accept a *Caller and inherit the chosen
	//    posture without recompiling". amsi-bypass.md line 126 and
	//    etw-patching.md line 110 both show *Caller as the single argument.
	tartarus := wsyscall.NewTartarus()
	fmt.Println("\n=== Consumer composability: amsi.PatchAll + etw.PatchAll ===")
	for _, m := range methods {
		runConsumers(m, tartarus)
	}
}

func runCell(label string, m wsyscall.Method, r wsyscall.SSNResolver) {
	caller := wsyscall.New(m, r)
	defer caller.Close()
	ret, err := caller.Call("NtClose", uintptr(0xDEAD))
	fmt.Printf("[%s] NtClose: ret=0x%X err=%v\n", label, ret, err)
}

func runConsumers(m wsyscall.Method, r wsyscall.SSNResolver) {
	caller := wsyscall.New(m, r)
	defer caller.Close()
	if err := amsi.PatchAll(caller); err != nil {
		fmt.Printf("[%s] amsi.PatchAll: %v\n", m, err)
	} else {
		fmt.Printf("[%s] amsi.PatchAll: OK\n", m)
	}
	if err := etw.PatchAll(caller); err != nil {
		fmt.Printf("[%s] etw.PatchAll: %v\n", m, err)
	} else {
		fmt.Printf("[%s] etw.PatchAll: OK\n", m)
	}
}
