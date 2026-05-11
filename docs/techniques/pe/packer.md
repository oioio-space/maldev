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
keyed independently; the operator gets back a `[]Step` slice they
need to replay (in reverse) to unpack.

```go
pipeline := []packer.Step{
    {Op: packer.OpCompress, Algo: uint8(packer.CompressorFlate)},
    {Op: packer.OpEncrypt,  Algo: uint8(packer.CipherAESGCM)},
}
blob, steps, err := packer.PackPipeline(payload, pipeline)
recovered, err := packer.UnpackPipeline(blob, steps)
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
    //   RandomizeStubSectionName  — `.mldv` → `.xxxxx` (Phase 2-A)
    //   RandomizeTimestamp        — COFF TimeDateStamp     (Phase 2-B)
    //   RandomizeLinkerVersion    — Optional Header        (Phase 2-C)
    //   RandomizeImageVersion     — Optional Header        (Phase 2-D)
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
