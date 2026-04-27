---
package: github.com/oioio-space/maldev/hash
last_reviewed: 2026-04-27
reflects_commit: f815d85
---

# Cryptographic hashes & ROR13

[← hash index](README.md) · [docs/index](../../index.md)

## TL;DR

One-shot hex-string wrappers around `crypto/md5`, `crypto/sha1`,
`crypto/sha256`, `crypto/sha512`, plus the ROR13 algorithm used by
shellcode for plaintext-free Win32 API resolution. Pure Go,
cross-platform, no system interaction.

## Primer

Two distinct use cases share this file:

The **cryptographic** wrappers (`MD5`, `SHA1`, `SHA256`, `SHA512`)
exist because Go's stdlib returns `[N]byte` arrays — convenient for
machines, awkward for logs, command-line output, and string-keyed maps.
The wrappers compress the boilerplate to one call and produce
lower-case hex strings.

**ROR13** is the canonical shellcode hash. Implants resolve Win32 APIs
without keeping plaintext function names in the binary by walking the
PE export directory of a loaded module and comparing each export name's
ROR13 hash against precomputed targets. The trailing-null variant
`ROR13Module` matches the convention used to hash module names from
`LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer`. `win/api.ResolveByHash`
consumes both.

The fuzzy hashes (ssdeep, TLSH) live in a separate page —
[fuzzy-hashing.md](fuzzy-hashing.md).

## How it works

### Cryptographic hashes

```mermaid
flowchart LR
    DATA[input bytes] --> H{algorithm}
    H -->|MD5| M[16-byte digest]
    H -->|SHA1| S1[20-byte digest]
    H -->|SHA256| S2[32-byte digest]
    H -->|SHA512| S5[64-byte digest]
    M --> HEX[lower-case hex string]
    S1 --> HEX
    S2 --> HEX
    S5 --> HEX
```

### ROR13

```mermaid
flowchart LR
    NAME[function name] --> ITER[for each byte b]
    ITER --> ROT[hash = ror32 hash, 13]
    ROT --> ADD[hash += b]
    ADD --> NEXT{more bytes?}
    NEXT -->|yes| ITER
    NEXT -->|no| OUT[uint32 hash]
```

`ROR13Module` adds a trailing null byte to the input, then hashes —
mirroring the wide-string traversal a PEB-walk shellcode performs over
the unicode `BaseDllName`.

The arithmetic per byte:

$$
\text{hash}_{i+1} = \big(\text{hash}_i \mathbin{\text{ror}} 13\big) + b_i \mod 2^{32}
$$

starting at $\text{hash}_0 = 0$. Pure 32-bit unsigned arithmetic, easy
to encode in a few shellcode bytes.

## API Reference

### `MD5(data []byte) string`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/hash#MD5)

Lower-case hex digest of `md5.Sum(data)`. 32 hex characters.

> [!CAUTION]
> MD5 is collision-broken. Use only for non-security identifiers
> (cache keys, log correlation). Never for integrity checks.

### `SHA1(data []byte) string`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/hash#SHA1)

Lower-case hex digest. 40 hex characters.

> [!WARNING]
> SHA-1 is also collision-broken (SHAttered, 2017). Prefer SHA-256.

### `SHA256(data []byte) string`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/hash#SHA256)

Lower-case hex digest. 64 hex characters. The default integrity hash.

### `SHA512(data []byte) string`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/hash#SHA512)

Lower-case hex digest. 128 hex characters. Use when truncation-resistant
output is required.

### `ROR13(name string) uint32`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/hash#ROR13)

Compute the 32-bit ROR13 hash of `name`. Case-sensitive. Used to match
Win32 export names exactly as they appear in the export directory.

**Example output:** `ROR13("LoadLibraryA") == 0xec0e4e8e`.

### `ROR13Module(name string) uint32`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/hash#ROR13Module)

Same as `ROR13` but appends a null terminator before hashing — matches
the convention that PEB-walk shellcode uses when hashing module names
from `LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer`.

## Examples

### Simple

```go
fmt.Println(hash.SHA256([]byte("payload")))
// 239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5

fmt.Printf("%#x\n", hash.ROR13("LoadLibraryA"))
// 0xec0e4e8e
```

See `ExampleSHA256`, `ExampleROR13`, `ExampleROR13Module` in
[`hash_example_test.go`](../../../hash/hash_example_test.go).

### Composed (precompute API hashes for a resolver)

```go
import "github.com/oioio-space/maldev/hash"

// Precomputed table for the resolver to consume.
var apiHashes = map[string]uint32{
    "LoadLibraryA":    hash.ROR13("LoadLibraryA"),
    "GetProcAddress":  hash.ROR13("GetProcAddress"),
    "VirtualAlloc":    hash.ROR13("VirtualAlloc"),
    "VirtualProtect":  hash.ROR13("VirtualProtect"),
}
```

### Advanced (`hash` + `win/api.ResolveByHash`)

```go
import (
    "github.com/oioio-space/maldev/hash"
    "github.com/oioio-space/maldev/win/api"
)

// At runtime — no plaintext "VirtualAlloc" string in the binary.
addr, err := api.ResolveByHash(
    hash.ROR13Module("kernel32.dll"),
    hash.ROR13("VirtualAlloc"),
)
```

### Complex (full resolver bootstrap pipeline)

```go
import (
    "github.com/oioio-space/maldev/hash"
    "github.com/oioio-space/maldev/win/api"
)

type Resolver struct {
    handle uintptr
}

func NewResolver(moduleHash uint32) (*Resolver, error) {
    h, err := api.GetModuleHandleByHash(moduleHash)
    if err != nil { return nil, err }
    return &Resolver{handle: h}, nil
}

func (r *Resolver) Resolve(funcName string) (uintptr, error) {
    return api.GetProcAddressByHash(r.handle, hash.ROR13(funcName))
}

func main() {
    k32, _ := NewResolver(hash.ROR13Module("kernel32.dll"))
    valloc, _ := k32.Resolve("VirtualAlloc")
    _ = valloc
}
```

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| Hex strings (especially SHA-256-shaped 64-char) in process memory | YARA over RW pages — hash strings are themselves a tell |
| Constant `0xec0e4e8e`-class 32-bit values stored in `.rdata` | Static analysis: known-API ROR13 hash tables are publicly catalogued (e.g. `ror13_hashes.csv` from various reversing tools) |
| Absence of `LoadLibraryA` / `GetProcAddress` plaintext in IAT despite using the APIs | Defenders flag "no IAT entries for `kernel32` but a `kernel32` handle is held" |
| ROR13 resolution loop signature (`ror eax, 13; add eax, ebx`) in `.text` | Capa, IDA signature plugins, MAEC ML classifiers |

**D3FEND counters:**

- [D3-SEA](https://d3fend.mitre.org/technique/d3f:StaticExecutableAnalysis/)
  — static EXE analysis catches the hash table or the ROR13 loop.
- [D3-PSA](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/)
  — flags processes that resolve APIs after a delay (typical of
  packers).

**Hardening:** spread API resolution across the binary's lifetime
rather than batching at startup; randomise hash constants per build (a
salt fed into `ROR13`'s initial state); pair with sleep-masking so the
resolved-address table does not sit decrypted in heap.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | ROR13 API hashing — no plaintext API names | D3-SEA |
| [T1027.007](https://attack.mitre.org/techniques/T1027/007/) | Dynamic API Resolution | ROR13 resolver pattern | D3-SEA |

The cryptographic hash wrappers themselves are utility — no MITRE
mapping.

## Limitations

- **MD5 and SHA-1 are broken.** Avoid for any integrity / signature use
  case. The package keeps them only because some legacy formats (e.g.
  PE Authenticode V1, NTLM) require MD5/SHA-1.
- **ROR13 is case-sensitive.** Hash mismatches between
  `LoadLibraryA` and `loadlibrarya` are silent — you'll fail to
  resolve and the call returns `nil`. Use `ROR13Module` for module
  names where Windows is case-insensitive (the function takes care of
  the null suffix; case still matters).
- **No streaming API.** Every wrapper takes the whole buffer. For
  multi-GB inputs, use `crypto/sha256.New()` directly and `io.Copy`
  into it.

## See also

- [API hashing technique page](../syscalls/api-hashing.md) — full
  walkthrough of the shellcode-side use of ROR13.
- [`fuzzy-hashing.md`](fuzzy-hashing.md) — ssdeep + TLSH for variant
  detection.
- [`win/api.ResolveByHash`](../syscalls/api-hashing.md) — primary
  consumer of `ROR13`.
- [`pe/morph`](../pe/morph.md) — uses fuzzy hashing internally to
  verify post-morph similarity.
