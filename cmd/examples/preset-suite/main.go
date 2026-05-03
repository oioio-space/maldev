//go:build windows

// preset-suite — panorama 18 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/evasion/preset.md  — 4 presets (Minimal /
//                                           Stealth / Hardened /
//                                           Aggressive) + CETOptOut
//                                           standalone Technique
//   - docs/techniques/syscalls/direct-indirect.md — preset.md's
//                                           canonical caller is
//                                           MethodIndirect + Tartarus
//
// Closes the open row in backlog P2.7: "Re-test each preset E2E in
// the VM matrix". Applies each preset in order with the doc-canonical
// caller and logs per-technique outcomes via the map returned by
// evasion.ApplyAll.
//
// Order matters: Aggressive runs LAST because acg.Guard locks the
// process out of further RWX allocation, which would break any
// subsequent preset run in the same process.
package main

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/preset"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
	caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewTartarus())
	defer caller.Close()

	suites := []struct {
		name  string
		techs []evasion.Technique
	}{
		{"Minimal", preset.Minimal()},
		{"Stealth", preset.Stealth()},
		{"Hardened", preset.Hardened()},
		{"Aggressive", preset.Aggressive()},
	}

	for _, s := range suites {
		fmt.Printf("\n=== preset.%s (%d techniques) ===\n", s.name, len(s.techs))
		errs := evasion.ApplyAll(s.techs, caller)
		if len(errs) == 0 {
			fmt.Printf("[%s] all techniques applied cleanly\n", s.name)
			continue
		}
		for techName, err := range errs {
			fmt.Printf("[%s/%s] FAIL: %v\n", s.name, techName, err)
		}
	}

	// CETOptOut as standalone — preset.md line 86 promises it can be
	// dropped into any caller's own technique slice. Verify the wrapper
	// still applies cleanly after Aggressive (CET is process-wide but
	// the technique is no-op when CET isn't enforced, idempotent when
	// it is).
	fmt.Println("\n=== preset.CETOptOut (standalone) ===")
	if err := preset.CETOptOut().Apply(caller); err != nil {
		fmt.Printf("[CETOptOut] FAIL: %v\n", err)
	} else {
		fmt.Println("[CETOptOut] OK")
	}
}
