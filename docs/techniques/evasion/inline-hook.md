# Inline Hook — x64 Function Interception

[<- Back to Evasion](README.md)

**MITRE ATT&CK:** [T1574.012](https://attack.mitre.org/techniques/T1574/012/) — Hijack Execution Flow: Inline Hooking
**Package:** `evasion/hook`
**Platform:** Windows (x64)
**Detection:** High

---

## What It Does

Intercepts calls to any exported Windows function by patching its prologue
with a JMP to a Go callback. The original function remains callable via a
trampoline. Pure Go — no CGo, no x64dbg required.

## How It Works

```mermaid
sequenceDiagram
    participant Caller
    participant Target as Target Function
    participant Relay as Relay Page (±2GB)
    participant Callback as Go Callback
    participant Trampoline as Trampoline

    Note over Target: Prologue patched with JMP rel32
    Caller->>Target: Call function
    Target->>Relay: JMP rel32 (5 bytes)
    Relay->>Callback: MOV R10, addr; JMP R10
    Callback->>Trampoline: syscall.SyscallN(h.Trampoline(), ...)
    Trampoline->>Target: Stolen bytes + JMP back past patch
    Target-->>Trampoline: Returns
    Trampoline-->>Callback: Returns
    Callback-->>Caller: Returns (possibly modified)
```

### Three Components

| Component | Size | Purpose |
|-----------|------|---------|
| **Hook patch** | 5 bytes (`E9 rel32`) | JMP from target to relay |
| **Relay page** | 13 bytes (`MOV R10, imm64; JMP R10`) | Absolute JMP to Go callback. Allocated within ±2GB of target (required for rel32). |
| **Trampoline** | N+13 bytes | Copy of stolen prologue bytes (with RIP fixups) + absolute JMP back to original function after the patch |

### Automatic Prologue Analysis

Uses `golang.org/x/arch/x86/x86asm` to:
1. Decode instructions until cumulative length >= 5 bytes
2. Detect RIP-relative instructions (`[RIP+disp32]`, relative branches)
3. Fix up displacements so the trampoline targets correct addresses

No manual `stealLength` calculation needed.

## API

```go
func Install(targetAddr uintptr, handler interface{}) (*Hook, error)
func InstallByName(dllName, funcName string, handler interface{}) (*Hook, error)

type Hook struct{ ... }
func (h *Hook) Remove() error
func (h *Hook) Trampoline() uintptr
func (h *Hook) Target() uintptr
```

## Usage

### Intercept and Log

```go
import (
    "log"
    "syscall"
    "unsafe"

    "github.com/oioio-space/maldev/evasion/hook"
    "golang.org/x/sys/windows"
)

var h *hook.Hook

func main() {
    var err error
    h, err = hook.InstallByName("kernel32.dll", "DeleteFileW",
        func(lpFileName uintptr) uintptr {
            name := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(lpFileName)))
            log.Printf("DeleteFileW: %s", name)
            r, _, _ := syscall.SyscallN(h.Trampoline(), lpFileName)
            return r
        },
    )
    if err != nil {
        log.Fatal(err)
    }
    defer h.Remove()

    // All DeleteFileW calls in this process now go through our handler.
    select {}
}
```

### Block an API Call

```go
var h *hook.Hook
h, _ = hook.InstallByName("kernel32.dll", "DeleteFileW",
    func(lpFileName uintptr) uintptr {
        return 0 // Return FALSE — deletion blocked
    },
)
defer h.Remove()
```

### Monitor NtCreateFile

```go
var h *hook.Hook
h, _ = hook.InstallByName("ntdll.dll", "NtCreateFile",
    func(fileHandle, desiredAccess, objAttrs, ioStatus, allocSize,
         fileAttrs, shareAccess, createDisp, createOpts, eaBuffer,
         eaLength uintptr) uintptr {
        log.Println("NtCreateFile intercepted")
        r, _, _ := syscall.SyscallN(h.Trampoline(),
            fileHandle, desiredAccess, objAttrs, ioStatus, allocSize,
            fileAttrs, shareAccess, createDisp, createOpts, eaBuffer, eaLength)
        return r
    },
)
defer h.Remove()
```

## Advantages & Limitations

| Aspect | Detail |
|--------|--------|
| **Pure Go** | No CGo — uses `syscall.NewCallback` |
| **Auto analysis** | Prologue decoded via `x86asm` |
| **RIP fixup** | RIP-relative instructions patched in trampoline |
| **Trampoline** | Original function remains callable |
| **Max params** | ~18 uintptr parameters (NewCallback limit) |
| **Scope** | Current process only |
| **Thread safety** | Brief race window during patch (non-atomic write) |
| **Go runtime** | Don't hook NtClose, NtCreateFile, NtReadFile, NtWriteFile |

## Comparison with evasion/unhook

| | `evasion/hook` | `evasion/unhook` |
|---|---|---|
| **Direction** | Installs hooks (intercept) | Removes hooks (restore) |
| **Use case** | API monitoring, redirection | EDR bypass |
| **Complementary** | Unhook EDR first, then install your own hooks |

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Hijack Execution Flow: Inline Hooking | [T1574.012](https://attack.mitre.org/techniques/T1574/012/) |

## Detection

**High** — Any integrity check comparing in-memory function prologues to
their on-disk counterparts will detect the JMP patch. EDR products
specifically monitor for this on sensitive functions.
