//go:build windows

// unhook-suite — panorama 4 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/evasion/ntdll-unhooking.md  — ClassicUnhook, FullUnhook,
//                                                  PerunUnhook, IsHooked
//   - docs/techniques/syscalls/{direct-indirect,ssn-resolvers}.md
//
// Tests each unhook variant against three caller backends (WinAPI fallback,
// Indirect+Tartarus, IndirectAsm+HashGate) so the matrix shows whether
// any caller/resolver combination produces a different result. On a clean
// VM with no EDR, IsHooked should already be false everywhere; the
// interesting signal is whether each unhook *call* succeeds vs returns an
// admin-required error.
package main

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion/unhook"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
	probes := []string{
		"NtAllocateVirtualMemory",
		"NtCreateThreadEx",
		"NtProtectVirtualMemory",
	}

	// 1. Initial hook check — IsHooked is doc-listed at line 195.
	fmt.Println("=== IsHooked baseline ===")
	for _, fn := range probes {
		if h, err := unhook.IsHooked(fn); err != nil {
			fmt.Printf("%s: err=%v\n", fn, err)
		} else {
			fmt.Printf("%s: hooked=%v\n", fn, h)
		}
	}

	// 2. ClassicUnhook with each caller backend (3rd arg = Opener; nil =
	//    path-based read, sufficient for an audit run).
	fmt.Println("\n=== ClassicUnhook variants ===")
	type backend struct {
		label  string
		caller *wsyscall.Caller
	}
	backends := []backend{
		{"nil-caller (WinAPI fallback)", nil},
		{"Indirect+Tartarus", wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewTartarus())},
		{"IndirectAsm+HashGate", wsyscall.New(wsyscall.MethodIndirectAsm, wsyscall.NewHashGate())},
	}
	defer func() {
		for _, b := range backends {
			if b.caller != nil {
				b.caller.Close()
			}
		}
	}()
	for _, b := range backends {
		err := unhook.ClassicUnhook("NtAllocateVirtualMemory", b.caller, nil)
		if err != nil {
			fmt.Printf("[%s] ClassicUnhook: %v\n", b.label, err)
		} else {
			fmt.Printf("[%s] ClassicUnhook: OK\n", b.label)
		}
	}

	// 3. FullUnhook — a full ntdll .text replacement. Doc warns this is the
	//    noisiest variant (ntdll-unhooking.md "Stealth (Full): Low").
	fmt.Println("\n=== FullUnhook ===")
	if err := unhook.FullUnhook(nil, nil); err != nil {
		fmt.Printf("FullUnhook: %v\n", err)
	} else {
		fmt.Printf("FullUnhook: OK\n")
	}

	// 4. PerunUnhook — load-from-fresh-process variant. Doc says no disk
	//    read, so it should not need any kind of admin file access.
	fmt.Println("\n=== PerunUnhook ===")
	if err := unhook.PerunUnhook(nil); err != nil {
		fmt.Printf("PerunUnhook: %v\n", err)
	} else {
		fmt.Printf("PerunUnhook: OK\n")
	}
	if err := unhook.PerunUnhookTarget("svchost.exe", nil); err != nil {
		fmt.Printf("PerunUnhookTarget(svchost.exe): %v\n", err)
	} else {
		fmt.Printf("PerunUnhookTarget(svchost.exe): OK\n")
	}

	// 5. Re-check IsHooked after the unhook passes. Should still be false
	//    on a clean VM, but the round-trip proves the API surface is live.
	fmt.Println("\n=== IsHooked after unhook ===")
	for _, fn := range probes {
		if h, err := unhook.IsHooked(fn); err != nil {
			fmt.Printf("%s: err=%v\n", fn, err)
		} else {
			fmt.Printf("%s: hooked=%v\n", fn, h)
		}
	}
}
