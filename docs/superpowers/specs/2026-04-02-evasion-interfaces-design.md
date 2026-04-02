# Evasion Composable Interfaces — Design Spec

**Date:** 2026-04-02
**Status:** Approved
**Module:** github.com/oioio-space/maldev

---

## 1. Goals

- Replace hardcoded boolean `EvasionConfig` with composable `Technique` interface
- Add per-function unhook with detection of hooked functions
- Make antiVM parameterizable with process detection, CPUID, and enriched vendors
- Make antiSandbox parameterizable with `CheckAll()`, process check, and configurable check set
- Add `context.Context` to evasion functions that may block

---

## 2. Technique Interface

### File: `evasion/evasion.go` (new)

```go
package evasion

import wsyscall "github.com/oioio-space/maldev/win/syscall"

// Technique is a single evasion action.
type Technique interface {
    Name() string
    Apply(caller *wsyscall.Caller) error
}

// ApplyAll executes all techniques. Returns a map of name -> error for failures.
// Successful techniques are not included. Empty map = all succeeded.
func ApplyAll(techniques []Technique, caller *wsyscall.Caller) map[string]error
```

### Presets: `evasion/preset.go` (new, Windows-only)

```go
func Minimal() []Technique    // AMSI + ETW
func Stealth() []Technique    // AMSI + ETW + NtTraceEvent + unhook common
func Aggressive() []Technique // AMSI + ETW + NtTraceEvent + unhook full + ACG + blockdlls
```

### Each technique package exports a constructor returning `Technique`:

```go
// evasion/amsi/
func ScanBufferPatch() evasion.Technique
func OpenSessionPatch() evasion.Technique
func All() evasion.Technique

// evasion/etw/
func PatchTechnique() evasion.Technique   // patches all 5 EtwEventWrite*
func NtTraceTechnique() evasion.Technique
func All() evasion.Technique

// evasion/unhook/
func Classic(funcName string) evasion.Technique
func ClassicAll(funcNames []string) []evasion.Technique
func CommonClassic() []evasion.Technique
func Full() evasion.Technique
func Perun(target string) evasion.Technique

// evasion/acg/
func Guard() evasion.Technique

// evasion/blockdlls/
func MicrosoftOnly() evasion.Technique
```

### Shell integration:

```go
// Before (boolean bag):
cfg := &shell.Config{
    Evasion: &shell.EvasionConfig{PatchAMSI: true, PatchETW: true},
}

// After (composable):
cfg := &shell.Config{
    Evasion: evasion.Stealth(),
    // or custom:
    Evasion: []evasion.Technique{
        amsi.ScanBufferPatch(),
        etw.All(),
        unhook.Classic("NtAllocateVirtualMemory"),
    },
}
```

The `EvasionConfig` struct is removed. `shell.Config.Evasion` becomes `[]evasion.Technique`.

---

## 3. Unhook Selective + Detection

### New functions in `evasion/unhook/`

```go
// CommonHookedFunctions lists NT functions commonly hooked by EDR.
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

// DetectHooked checks which functions have modified prologues.
// Compares first 4 bytes against the standard ntdll x64 pattern (4C 8B D1 B8).
// Returns only the names that appear hooked.
func DetectHooked(funcNames []string) ([]string, error)

// Classic returns a Technique that restores the first bytes of funcName from disk.
func Classic(funcName string) evasion.Technique

// ClassicAll returns one Technique per function name.
func ClassicAll(funcNames []string) []evasion.Technique

// CommonClassic returns ClassicAll(CommonHookedFunctions).
func CommonClassic() []evasion.Technique

// Full returns a Technique that restores the entire ntdll .text section from disk.
func Full() evasion.Technique

// Perun returns a Technique that restores ntdll from a suspended child process.
// If target is empty, defaults to "C:\Windows\System32\svchost.exe".
func Perun(target string) evasion.Technique
```

Existing `ClassicUnhook`, `FullUnhook`, `PerunUnhook` remain as direct-call API.

---

## 4. AntiVM Parameterizable

### Types

```go
type CheckType uint

const (
    CheckRegistry CheckType = 1 << iota
    CheckFiles
    CheckNIC
    CheckProcess
    CheckCPUID
    CheckAll = CheckRegistry | CheckFiles | CheckNIC | CheckProcess | CheckCPUID
)

type Config struct {
    Vendors []Vendor   // nil = DefaultVendors
    Checks  CheckType  // 0 = CheckAll
}

type Vendor struct {
    Name  string
    Keys  []RegKey   // Windows only (ignored on Linux)
    Files []string
    Nic   []string
    Proc  []string   // NEW — process names
}
```

### New functions

```go
func DefaultConfig() Config
func Detect(cfg Config) (string, error)
func DetectAll(cfg Config) ([]string, error)
func DetectProcess(procNames []string) (bool, string, error)
func DetectCPUID() (bool, string)  // cross-platform, checks hypervisor bit
```

### Enriched DefaultVendors

Recover `Proc` field from legacy code. Add:
- Hyper-V: vmicheartbeat, vmicshutdown
- VirtualBox: vboxservice, vboxtray, vboxclient
- VMware: vmtoolsd, vmwaretray, vmwareuser, vmacthlp
- Xen: xenservice, xenstored
- QEMU: qemu-ga
- Parallels: prl_cc, prl_tools
- VirtualPC: vmsrvc, vmusrvc

Add new vendors: KVM, Docker, WSL.

### Linux unification

Linux uses the same `Vendor` struct. `Keys` field is ignored. `Files`, `Proc`, `Nic` work on both platforms. `DetectCPUID` is cross-platform.

---

## 5. AntiSandbox Parameterizable

### Types

```go
type Result struct {
    Name     string
    Detected bool
    Detail   string
    Err      error
}

type Config struct {
    MinDiskGB      float64
    MinRAMGB       float64
    MinCPUCores    int
    DiskPath       string          // default: "C:\" or "/"
    BadUsernames   []string
    BadHostnames   []string
    BadProcesses   []string        // NEW
    FakeDomain     string
    RequestTimeout time.Duration   // NEW — default 5s
    StopOnFirst    bool            // NEW — default true
}
```

### New API

```go
func New(cfg Config) *Checker       // replaces NewChecker (anti-stutter)
func (c *Checker) CheckAll() []Result  // NEW — returns all results
func (c *Checker) CheckProcesses() (bool, string, error)  // NEW
```

### DefaultConfig enriched

Add `BadProcesses` with analysis tool names:
wireshark, procmon, procexp, x64dbg, x32dbg, ollydbg, ida, ida64,
fiddler, httpdebugger, burpsuite, processhacker, tcpview, autoruns,
pestudio, dnspy, ghidra

---

## 6. Context Support

Functions that may block (network, process enumeration) accept `context.Context`:

```go
func (c *Checker) IsSandboxed(ctx context.Context) (bool, string, error)
func (c *Checker) CheckAll(ctx context.Context) []Result
func (c *Checker) FakeDomainReachable(ctx context.Context) (bool, int, error)
```

---

## 7. Files Changed

| File | Action |
|------|--------|
| `evasion/evasion.go` | NEW — Technique interface + ApplyAll |
| `evasion/preset_windows.go` | NEW — Minimal, Stealth, Aggressive |
| `evasion/preset_stub.go` | NEW — non-Windows empty presets |
| `evasion/amsi/technique.go` | NEW — ScanBufferPatch(), All() returning Technique |
| `evasion/etw/technique.go` | NEW — PatchTechnique(), All() returning Technique |
| `evasion/unhook/technique.go` | NEW — Classic(), Full(), Perun() returning Technique |
| `evasion/unhook/detect.go` | NEW — DetectHooked(), CommonHookedFunctions |
| `evasion/acg/technique.go` | NEW — Guard() returning Technique |
| `evasion/blockdlls/technique.go` | NEW — MicrosoftOnly() returning Technique |
| `evasion/antivm/antivm_windows.go` | MODIFY — add Config, Detect, DetectAll, DetectProcess, Proc field |
| `evasion/antivm/antivm_linux.go` | MODIFY — unify to use Vendor struct, add DetectProcess |
| `evasion/antivm/cpuid.go` | NEW — DetectCPUID cross-platform |
| `evasion/sandbox/sandbox.go` | MODIFY — Config enriched, New(), Result type |
| `evasion/sandbox/sandbox_windows.go` | MODIFY — CheckAll, CheckProcesses, context support |
| `evasion/sandbox/sandbox_linux.go` | MODIFY — same |
| `c2/shell/shell.go` | MODIFY — Evasion field becomes []evasion.Technique |
| `c2/shell/evasion_windows.go` | MODIFY — applyEvasion uses Technique.Apply loop |
| `c2/shell/evasion_stub.go` | MODIFY — match new signature |
| README.md | MODIFY — update examples |
