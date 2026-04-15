# Architecture

[← Back to README](../README.md)

## Layered Design

maldev follows a strict bottom-up dependency model. Each layer only depends on layers below it.

```mermaid
graph TD
    subgraph "Layer 0 — Pure Go (no OS calls)"
        crypto["crypto/"]
        encode["encode/"]
        hash["hash/"]
        random["random/"]
        useragent["useragent/"]
    end

    subgraph "Layer 1 — OS Primitives"
        api["win/api<br/>DLL handles, PEB walk, API hashing"]
        syscall["win/syscall<br/>Direct/Indirect syscalls, HashGate"]
        ntapi["win/ntapi<br/>Typed NT wrappers, handle enum"]
        token["win/token<br/>Token manipulation"]
        privilege["win/privilege<br/>Elevation helpers"]
        impersonate["win/impersonate<br/>Thread impersonation"]
        version["win/version<br/>Version detection"]
        domain["win/domain<br/>Domain membership"]
    end

    subgraph "Layer 2 — Techniques"
        inject["inject/<br/>15 injection methods"]
        evasion["evasion/<br/>15 evasion techniques"]
        cleanup["cleanup/<br/>Memory, files, timestamps"]
        pe["pe/<br/>Parse, strip, morph, BOF, srdi, cert, clr, winres"]
        process["process/<br/>Enum, session"]
        system["system/<br/>ads, drive, folder, network, lnk, bsod, ui"]
        uacbypass["uacbypass/"]
    end

    subgraph "Layer 3 — Orchestration"
        shell["c2/shell<br/>Reverse shell + state machine"]
        meterpreter["c2/meterpreter<br/>Metasploit staging"]
        transport["c2/transport<br/>TCP, TLS, uTLS, Malleable HTTP"]
        cert["c2/cert<br/>Certificate generation"]
        exploit["exploit/<br/>CVE-2024-30088"]
    end

    %% Dependencies
    api --> hash
    syscall --> api
    ntapi --> api
    inject --> api
    inject --> syscall
    evasion --> api
    evasion --> syscall
    shell --> transport
    shell --> evasion
    meterpreter --> transport
    meterpreter --> inject
    meterpreter --> useragent
    exploit --> ntapi
    exploit --> token
    exploit --> inject
```

## Caller Pattern

The `*wsyscall.Caller` is the central OPSEC mechanism. Any function that calls NT syscalls accepts an optional Caller parameter:

```mermaid
flowchart LR
    A[Your Code] --> B{Caller?}
    B -->|nil| C[Standard WinAPI<br/>kernel32 → ntdll]
    B -->|WinAPI| C
    B -->|NativeAPI| D[ntdll directly]
    B -->|Direct| E[Syscall stub<br/>in RW→RX page]
    B -->|Indirect| F[Jump to ntdll<br/>syscall;ret gadget]

    E --> G[SSN Resolver]
    F --> G
    G --> H{Resolver Type}
    H -->|HellsGate| I[Read prologue]
    H -->|HalosGate| J[Scan neighbors]
    H -->|TartarusGate| K[Follow JMP hook]
    H -->|HashGate| L[PEB walk + ROR13]
```

## Evasion Composition

Evasion techniques compose via the `evasion.Technique` interface:

```mermaid
flowchart TD
    A[Configure Techniques] --> B["techniques := []evasion.Technique{
        amsi.ScanBufferPatch(),
        etw.All(),
        unhook.Full(),
    }"]
    B --> C["evasion.ApplyAll(techniques, caller)"]
    C --> D{Each technique}
    D --> E[AMSI: Patch prologue]
    D --> F[ETW: Patch 6 functions]
    D --> G[Unhook: Restore .text]
    E --> H[Ready for injection]
    F --> H
    G --> H
```

## Memory Protection Lifecycle

All injection methods follow the RW→RX pattern (never RWX):

```mermaid
stateDiagram-v2
    [*] --> Allocate: VirtualAlloc(PAGE_READWRITE)
    Allocate --> Write: Copy shellcode
    Write --> Protect: VirtualProtect(PAGE_EXECUTE_READ)
    Protect --> Execute: CreateThread / APC / Callback
    Execute --> Cleanup: WipeAndFree / Sleep Mask
    Cleanup --> [*]

    state "Sleep Mask Cycle" as SM {
        [*] --> Encrypt: XOR + PAGE_READWRITE
        Encrypt --> Sleep: time.Sleep / BusyWaitTrig
        Sleep --> Decrypt: XOR + Restore original
        Decrypt --> [*]
    }

    Execute --> SM: Between beacons
    SM --> Execute: Wake up
```

## Build Pipeline

```mermaid
flowchart LR
    A[Source Code] --> B[garble -literals -tiny]
    B --> C[go build -trimpath -ldflags='-s -w']
    C --> D[pe/strip.Sanitize]
    D --> E[Optional: UPX pack]
    E --> F[pe/morph.UPXMorph]
    F --> G[Final Binary]

    style B fill:#f96
    style D fill:#f96
    style F fill:#f96
```
