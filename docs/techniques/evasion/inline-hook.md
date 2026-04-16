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

## How to Find the Right Function to Hook

You don't need x64dbg. Windows API functions are exported by name from
system DLLs — `InstallByName` resolves them automatically.

### Step 1: Identify the API

Ask: "What Windows API does the operation I want to intercept call?"

| I want to intercept... | Hook this function | In this DLL |
|------------------------|-------------------|-------------|
| File deletion | `DeleteFileW` | `kernel32.dll` |
| File creation/opening | `NtCreateFile` | `ntdll.dll` |
| Process creation | `CreateProcessW` | `kernel32.dll` |
| Registry writes | `RegSetValueExW` | `advapi32.dll` |
| Network connections | `connect` | `ws2_32.dll` |
| DNS resolution | `DnsQuery_W` | `dnsapi.dll` |
| MessageBox | `MessageBoxW` | `user32.dll` |
| Memory allocation | `NtAllocateVirtualMemory` | `ntdll.dll` |
| DLL loading | `LdrLoadDll` | `ntdll.dll` |
| Screenshot | `BitBlt` | `gdi32.dll` |

**Tip:** Hook the `Nt*` (ntdll) version to catch all callers — kernel32
functions like `CreateFileW` internally call `NtCreateFile`, so hooking
at the ntdll level catches both direct and indirect calls.

### Step 2: Find the Signature

Look up the function signature on [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/).
Convert each parameter to `uintptr` in your Go handler:

```
// MSDN signature:
// BOOL DeleteFileW(LPCWSTR lpFileName)
//
// Go handler:
func(lpFileName uintptr) uintptr

// MSDN signature:
// NTSTATUS NtCreateFile(
//   PHANDLE FileHandle,
//   ACCESS_MASK DesiredAccess,
//   POBJECT_ATTRIBUTES ObjectAttributes,
//   PIO_STATUS_BLOCK IoStatusBlock,
//   PLARGE_INTEGER AllocationSize,
//   ULONG FileAttributes,
//   ULONG ShareAccess,
//   ULONG CreateDisposition,
//   ULONG CreateOptions,
//   PVOID EaBuffer,
//   ULONG EaLength
// )
//
// Go handler: all pointers and integers become uintptr
func(fileHandle, desiredAccess, objAttrs, ioStatus, allocSize,
     fileAttrs, shareAccess, createDisp, createOpts, eaBuffer,
     eaLength uintptr) uintptr
```

### Step 3: Write the Hook

```go
package main

import (
    "fmt"
    "log"
    "os"
    "syscall"
    "unsafe"

    "github.com/oioio-space/maldev/evasion/hook"
    "golang.org/x/sys/windows"
)

var hDeleteFile *hook.Hook

func main() {
    var err error

    // Hook DeleteFileW — intercept all file deletions in this process.
    hDeleteFile, err = hook.InstallByName("kernel32.dll", "DeleteFileW",
        func(lpFileName uintptr) uintptr {
            name := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(lpFileName)))

            // Decide: block or allow?
            if name == `C:\important.txt` {
                log.Printf("BLOCKED deletion of %s", name)
                // Set last error and return FALSE
                windows.SetLastError(windows.ERROR_ACCESS_DENIED)
                return 0
            }

            // Allow — call original via trampoline.
            log.Printf("ALLOWED deletion of %s", name)
            r, _, _ := syscall.SyscallN(hDeleteFile.Trampoline(), lpFileName)
            return r
        },
    )
    if err != nil {
        log.Fatal(err)
    }
    defer hDeleteFile.Remove()

    // Test it — try to delete a file.
    err = os.Remove(`C:\important.txt`)
    fmt.Printf("Remove result: %v\n", err) // Access denied — hook blocked it

    err = os.Remove(`C:\temp\disposable.txt`)
    fmt.Printf("Remove result: %v\n", err) // Allowed — hook called original
}
```

### Step 4: List All Exports

To discover what functions a DLL exports (without x64dbg), use `debug/pe`:

```go
import "debug/pe"

f, _ := pe.Open(`C:\Windows\System32\kernel32.dll`)
defer f.Close()

exports, _ := f.Exports()
for _, e := range exports {
    fmt.Println(e.Name)
}
// Output: AcquireSRWLockExclusive, AddAtomA, AddAtomW, ...
```

### Finding Signatures Without MSDN

The PE export table only stores `name → address` — **no parameter types or
count**. This is a fundamental limitation of the PE format. Several
approaches exist depending on the context:

#### For Windows APIs: just use MSDN

Microsoft documents every public function. Search
`site:learn.microsoft.com <function name>` and translate to `uintptr`.

#### For unknown/third-party functions: estimate parameter count

Since Go handlers use `uintptr` for all parameters, you only need to know
**how many** params — not their types. The x64 ABI is predictable:

- First 4 args: `RCX`, `RDX`, `R8`, `R9`
- Additional args: pushed on stack after 32-byte shadow space
- `sub rsp, 0xNN` in the prologue hints at the frame size

**Practical shortcut:** declare more parameters than the function actually
takes. Extra `uintptr` args are harmless — the Go callback ignores them:

```go
// Don't know exact param count? Declare the maximum (up to 18).
// Unused params are simply zero.
h, _ = hook.Install(funcAddr, func(
    a1, a2, a3, a4, a5, a6, a7, a8 uintptr,
) uintptr {
    log.Printf("called with: %x %x %x %x", a1, a2, a3, a4)
    r, _, _ := syscall.SyscallN(h.Trampoline(), a1, a2, a3, a4, a5, a6, a7, a8)
    return r
})
```

#### For programs with debug symbols (.pdb)

Microsoft publishes PDB files for system binaries on the
[Symbol Server](https://msdl.microsoft.com/download/symbols). Third-party
programs sometimes ship with `.pdb` files next to the `.exe`. PDB files
contain full type information including parameter names and types. Parsing
requires a PDB reader (not yet in maldev).

#### Discovering imports of a target program

To see which DLL functions a program calls (and thus which are hookable
via IAT), parse its import table:

```go
import "debug/pe"

f, _ := pe.Open(`C:\path\to\target.exe`)
defer f.Close()

imports, _ := f.ImportedSymbols()
for _, sym := range imports {
    fmt.Println(sym) // "kernel32.dll:CreateFileW", "ntdll.dll:NtClose", etc.
}
```

This tells you exactly which functions the target uses — you can then look
up each one's signature by name.

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
