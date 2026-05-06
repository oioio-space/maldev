---
last_reviewed: 2026-04-29
reflects_commit: b81bd80
---

# Call-stack spoofing — metadata primitives

[← evasion area README](README.md) · [docs/index](../../index.md)

## TL;DR

When EDR sees `VirtualAllocEx` called, it walks the calling
thread's stack and asks "who got us here?". A real Win32 program
shows `RtlUserThreadStart → BaseThreadInitThunk → main → ...
→ VirtualAllocEx`. A Go injector shows `runtime.goexit → ...
→ syscall.Syscall6 → VirtualAllocEx` — instantly suspicious.

Spoofing the call stack rewrites the stack so the walker sees
the benign Win32 lineage instead.

The package splits into two halves with very different maturity:

| Layer | What you get | Status |
|---|---|---|
| **Metadata helpers** ([`StandardChain`](#standardchain-frame-error), [`FindReturnGadget`](#findreturngadget-uintptr-error), [`LookupFunctionEntry`](#lookupfunctionentry), [`Validate`](#validate)) | Build the synthetic Frame chain (`RtlUserThreadStart → BaseThreadInitThunk → …`) with valid RUNTIME_FUNCTION rows pulled from ntdll/kernel32 `.pdata`. Use independently of any pivot. | **Production-ready.** Used today by `evasion/preset` for stack metadata. |
| **Asm pivot** (`SpoofCall`) | Plants the chain on the thread's stack and JMPs into the target so the unwinder walks the synthetic frames | **Experimental scaffold** — gated behind `MALDEV_SPOOFCALL_E2E=1`, documented crash path. Use the metadata helpers + your own pivot for production. |

What the metadata helpers DO:

- Resolve `kernel32!BaseThreadInitThunk` + `ntdll!RtlUserThreadStart`
  via `RtlLookupFunctionEntry` so each Frame carries a *valid*
  RUNTIME_FUNCTION the unwinder will follow.
- Find a `RET` gadget in ntdll's `.text` so the CPU "lands"
  inside ntdll after the target returns — the unwinder then
  walks ntdll's full `.pdata` coverage.
- `Validate` catches structural mistakes (wrong unwind info,
  RIP out of `[Begin, End)`) before the chain hits a walker.

What this DOES NOT do:

- **Doesn't bypass ETW Threat-Intelligence cross-validation** —
  ETW's `Microsoft-Windows-Threat-Intelligence` provider can
  cross-check the walked RIPs against actual control flow. EDRs
  paying for ETW-TI subscriptions still see you.
- **Doesn't change WHAT the spoofed thread does** — only WHO it
  appears to call from. The actual `VirtualAllocEx` still
  happens; it just looks like it came from `BaseThreadInitThunk`.
- **`SpoofCall` is not safe** — the asm pivot is research
  scaffold. For production, use the metadata helpers
  (`StandardChain` returns a usable `[]Frame` chain) and write
  your own asm pivot tuned to your target's calling convention.

## Primer — vocabulary

Six terms recur on this page:

> **Stack walking** — the process of following return addresses
> on a thread's stack to reconstruct the chain of callers (the
> "back trace"). EDRs do this on suspicious API calls; debuggers
> do it for crash analysis.
>
> **`RtlVirtualUnwind`** — the user-mode function (and its
> kernel-mode sibling) that performs the actual stack-walk step.
> Given a current RIP, it looks up the matching RUNTIME_FUNCTION
> in the module's `.pdata` and follows the unwind info to compute
> the previous frame.
>
> **RUNTIME_FUNCTION** — a 12-byte record in a PE's `.pdata`
> section describing one function's start RVA, end RVA, and a
> pointer to its `UNWIND_INFO`. Without a RUNTIME_FUNCTION
> covering the current RIP, the unwinder can't proceed — which
> is why the spoof needs the fake "return address" to land
> INSIDE ntdll (full `.pdata` coverage).
>
> **`.pdata`** — the PE section holding all RUNTIME_FUNCTION
> entries for the module. Sorted by start RVA; binary-searched
> by `RtlLookupFunctionEntry`.
>
> **Thread-init lineage** — the canonical Win32 thread startup
> chain: `RtlUserThreadStart → BaseThreadInitThunk → main`.
> Every legitimate thread on Windows has these two frames at
> the bottom. Spoofing aims to make the walker SEE this lineage
> even when the actual code path didn't go through it.
>
> **RET gadget** — a single `RET` instruction (`0xC3`) somewhere
> in ntdll's `.text`. Used as the "land here after the target
> returns" address in the spoof. After the gadget RETs, the CPU
> pops the next address (the next frame in the chain) and
> continues.

## How It Works

```mermaid
sequenceDiagram
    participant G as "Caller (Go)"
    participant S as "Spoof pivot (asm)"
    participant T as "Target fn"
    participant W as "RtlVirtualUnwind"
    participant N as "ntdll RET gadget"

    Note over G: Build chain via StandardChain + FindReturnGadget
    G->>S: SpoofCall(target, chain, args)
    S->>S: Plant fakeRet then realRet on stack
    S->>T: JMP target (not CALL)
    Note over T: Executes body. RIP inside target.
    W->>T: Snapshot RIP at sampling moment
    W->>T: Lookup RUNTIME_FUNCTION RIP
    W-->>W: Unwinds via target .pdata
    W->>N: Lands on fakeRet, ntdll RET gadget
    W->>N: Lookup RUNTIME_FUNCTION fakeRet
    W-->>W: Walks ntdll frame metadata
    W-->>G: Reports BaseThreadInitThunk then RtlUserThreadStart

    T-->>N: RET pops fakeRet
    N-->>G: RET pops realRet, back to Go
```

Steps:

1. `StandardChain` resolves the canonical thread-init lineage:
   `kernel32!BaseThreadInitThunk` (inner caller) and
   `ntdll!RtlUserThreadStart` (outer caller). Both are looked up via
   `RtlLookupFunctionEntry` so the returned `Frame[i]` carries a
   valid `RUNTIME_FUNCTION` row from the legitimate module's
   `.pdata`.
2. `FindReturnGadget` scans `ntdll.dll`'s `.text` for a lone `RET`
   (`0xC3` followed by alignment padding). The address is used as
   the **fake return** at the top of the chain — when the target's
   own `RET` fires, the CPU jumps into ntdll's image, which has full
   `.pdata` coverage.
3. The asm pivot (`SpoofCall` scaffold, gated behind
   `MALDEV_SPOOFCALL_E2E=1`) plants `[fakeRet, ...chain]` on the
   thread's stack, then `JMP`s (not `CALL`s) into the target. When
   the target returns, it pops `fakeRet` and the CPU lands inside
   ntdll. A walker that samples `RIP` at any point above the target
   walks ntdll's metadata and reports a benign thread-init sequence.
4. `Validate` confirms structural consistency before any of this:
   non-zero return / image base / unwind-info; `ControlPc` bounded
   by the `RUNTIME_FUNCTION [Begin, End)` window.

## API Reference

```go
type Frame struct {
    ReturnAddress   uintptr
    ImageBase       uintptr
    RuntimeFunction RuntimeFunction
}

type RuntimeFunction struct {
    BeginAddress      uint32
    EndAddress        uint32
    UnwindInfoAddress uint32
}

func LookupFunctionEntry(addr uintptr) (Frame, error)
func StandardChain() ([]Frame, error)
func FindReturnGadget() (uintptr, error)
func Validate(chain []Frame) error

// Experimental — gated behind MALDEV_SPOOFCALL_E2E=1
func SpoofCall(target unsafe.Pointer, chain []Frame, args ...uintptr) (uintptr, error)
```

Sentinel errors: `ErrUnsupportedPlatform`,
`ErrFunctionEntryNotFound`, `ErrGadgetNotFound`,
`ErrEmptyChain`, `ErrTooManyArgs`.

### `LookupFunctionEntry(addr uintptr) (Frame, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack#LookupFunctionEntry)

Wraps `ntdll!RtlLookupFunctionEntry`. Given any instruction address
inside a loaded PE, returns a `Frame` populated with
`ReturnAddress` + `ImageBase` + `RUNTIME_FUNCTION` (copied by value).

**Parameters:**
- `addr` — any in-image RIP value. Out-of-image addresses return
  `ErrFunctionEntryNotFound`.

**Returns:**
- `Frame` — `ReturnAddress=addr`, `ImageBase`+`RuntimeFunction`
  populated from ntdll.
- `error` — `ErrFunctionEntryNotFound` if `addr` is outside any
  loaded module's `.pdata` coverage; `ErrUnsupportedPlatform` on
  non-amd64 / non-Windows.

**Side effects:** none — pure read.

**OPSEC:** silent. No syscall, no allocation, no telemetry trail.

**Required privileges:** `unprivileged`.

**Platform:** `windows` amd64.

### `StandardChain() ([]Frame, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack#StandardChain)

Returns a cached 2-frame chain rooted at the Windows thread-init
sequence: `[0]` `kernel32!BaseThreadInitThunk` (inner — direct
caller of target), `[1]` `ntdll!RtlUserThreadStart` (outer — thread
entry point). Both frames carry full `RUNTIME_FUNCTION` metadata.

**Parameters:** none.

**Returns:**
- `[]Frame` length 2. Returned by reference; do not mutate.
- `error` — `ErrFunctionEntryNotFound` when either symbol cannot be
  resolved (e.g., `kernel32`/`ntdll` not yet mapped); cached on
  first success.

**Side effects:** caches the chain on first call; subsequent calls
return the cached slice in O(1).

**OPSEC:** silent — only `RtlLookupFunctionEntry` reads.

**Required privileges:** `unprivileged`.

**Platform:** `windows` amd64.

### `FindReturnGadget() (uintptr, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack#FindReturnGadget)

Scans `ntdll.dll`'s `.text` for the first lone `RET` (`0xC3`
followed by `int3` / `nop` padding) and returns its absolute
address. Callers planting a fake return on the stack point there so
the target's `RET` jumps into a well-known ntdll address.

**Parameters:** none.

**Returns:**
- `uintptr` — address of an ntdll RET gadget. Cached.
- `error` — `ErrGadgetNotFound` only if ntdll's `.text` is hooked
  out of recognition (very unusual).

**Side effects:** caches the address on first call.

**OPSEC:** silent — single in-process memory walk.

**Required privileges:** `unprivileged`.

**Platform:** `windows` amd64.

### `Validate(chain []Frame) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack#Validate)

Checks structural consistency of the supplied chain.

**Parameters:**
- `chain` — caller-built `[]Frame`. May be the result of
  `StandardChain()` plus operator-added frames.

**Returns:**
- `error` — non-nil when any frame has zero
  `ReturnAddress`/`ImageBase`/`UnwindInfoAddress`, or when
  `ControlPc` falls outside `RuntimeFunction.[Begin, End)`. Nil on a
  valid chain.

**Side effects:** none.

**OPSEC:** silent.

**Required privileges:** `unprivileged`.

**Platform:** `windows` amd64 (struct alignment relies on amd64
`RUNTIME_FUNCTION` layout).

### `SpoofCall(target, chain, args...) (uintptr, error)` (experimental)

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack#SpoofCall)

Asm pivot. Plants `[fakeRet, ...chain]` on the stack, sets up Win64
ABI register passing for up to 4 args, and `JMP`s into `target`. The
target's eventual `RET` lands on `fakeRet` (an ntdll RET gadget); a
walker sampling RIP anywhere above the target sees ntdll-resident
addresses with valid `.pdata`.

**Parameters:**
- `target` — `unsafe.Pointer` to the function to invoke.
- `chain` — pre-validated `[]Frame` from `StandardChain` (+
  caller-supplied frames as needed).
- `args...` — up to 4 `uintptr` arguments mapped to RCX/RDX/R8/R9.

**Returns:**
- `uintptr` — the value the target left in RAX.
- `error` — `ErrEmptyChain` / `ErrTooManyArgs` on caller-side
  violations. Pivot itself does not return errors mid-flight (any
  fault is a crash).

**Side effects:** mutates the caller goroutine's stack frame for the
duration of the pivot; restored on return.

**OPSEC:** the spoofed walker view is the goal — sampling at the
target's RIP shows a benign thread-init lineage. Reflection-based
walkers that re-derive frames from CFG can still flag.

**Required privileges:** `unprivileged`.

**Platform:** `windows` amd64. Gated behind
`MALDEV_SPOOFCALL_E2E=1` until the
`lastcontinuehandler`-on-Go-runtime crash is root-caused.

## Examples

### Simple — build + validate a chain

```go
chain, err := callstack.StandardChain()
if err != nil {
    log.Fatal(err)
}
if err := callstack.Validate(chain); err != nil {
    log.Fatalf("chain invalid: %v", err)
}
gadget, err := callstack.FindReturnGadget()
if err != nil {
    log.Fatal(err)
}
log.Printf("chain frames=%d gadget=%#x", len(chain), gadget)
```

### Composed — chain + injection landing-site spoof

The chain is one piece of the deception. Pair it with
`evasion/unhook` and an indirect-syscall caller so a walker that
lands on any of the hot calls sees ntdll-resident addresses with
valid `.pdata`.

```go
import (
    "github.com/oioio-space/maldev/evasion/callstack"
    "github.com/oioio-space/maldev/inject"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

stdChain, _ := callstack.StandardChain()
_ = callstack.Validate(stdChain)
gadget, _ := callstack.FindReturnGadget()
gadgetFrame, _ := callstack.LookupFunctionEntry(gadget)
full := append([]callstack.Frame{gadgetFrame}, stdChain...)

caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewHashGate())
defer caller.Close()
inj, _ := inject.NewWindowsInjector(&inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodCreateThread},
    SyscallMethod: wsyscall.MethodIndirect,
})
_ = inj.Inject(shellcode)
_ = full // hand off to operator's own pivot OR callstack.SpoofCall
```

### Advanced — SpoofCall (gated)

```go
// MALDEV_SPOOFCALL_E2E=1 must be set; the asm pivot is debug-only.
chain, _ := callstack.StandardChain()
gadget, _ := callstack.FindReturnGadget()
gadgetFrame, _ := callstack.LookupFunctionEntry(gadget)
full := append([]callstack.Frame{gadgetFrame}, chain...)

target := unsafe.Pointer(windows.NewLazyDLL("ntdll.dll").
    NewProc("RtlGetVersion").Addr())
ret, err := callstack.SpoofCall(target, full /* no args */)
if err != nil {
    log.Fatalf("spoofcall: %v", err)
}
log.Printf("RtlGetVersion returned %#x", ret)
```

## OPSEC & Detection

| Vector | Visibility | Mitigation |
|---|---|---|
| `RtlLookupFunctionEntry` reads | not logged | none needed |
| Synthetic frame on the thread stack | reflection-based walkers may flag | live with the residual; pair with HW-BP variant (P2.6) on hardened targets |
| ETW Threat-Intelligence | cross-references RIP against legitimate call graph | EDRs subscribing to TI can still flag — `evasion/callstack` makes the chain *plausible*, not *indistinguishable* |
| ntdll RET-gadget address | static — same value across calls within a process | randomise gadget pick from `FindReturnGadget` candidates (future enhancement) |

D3FEND counters: **D3-PSA** (Process Spawn Analysis) — when paired
with a benign thread-init RIP sequence the spawn / call chain
appears legitimate.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | call-stack metadata | D3-PSA |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | runtime stack obfuscation | D3-EAL |

## Limitations

- **x64 only.** x86 uses frame-pointer walking rather than
  `.pdata`-based unwind, which requires a different spoof strategy.
- **Synthetic frames detected by ETW Threat-Intelligence.** Some
  EDRs (especially those consuming the TI provider) cross-check
  every stack frame RIP against the current call graph.
- **Module relocations.** `StandardChain` caches the frames after
  first call; if the target module unmaps + remaps at a new base
  (unusual but possible under ASLR-stressed environments), the
  cached frames become stale. Spawn a fresh process or build a
  one-shot chain via `LookupFunctionEntry`.
- **No hardware-breakpoint variant yet.** The fortra-style HWBP
  pivot (HW-BP on RET gadget for stronger obfuscation) is tracked
  under backlog row P2.6.
- **`SpoofCall` is experimental.** The pivot occasionally crashes
  through Go's `lastcontinuehandler` due to runtime M:N
  scheduling. Promotion to a tagged release waits on a clean
  root-cause.

## See also

- [Evasion area README](README.md)
- [`evasion/sleepmask`](sleep-mask.md) — pair with sleep-mask so spoofed frames are also wiped between callbacks
- [`win/syscall`](../syscalls/direct-indirect.md) — `MethodIndirect` returns into ntdll, complementary stack-stealth path
- [`recon/hwbp`](../recon/hw-breakpoints.md) — companion HW-BP variant tracked under backlog P2.6
- [package godoc](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack)
