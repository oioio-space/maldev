---
last_reviewed: 2026-05-06
status: design + Phase 1a + 1b shipped (v0.50.0 + v0.51.0); Phase 1c+ in progress
---

# `pe/packer` design — scope, threat model, phases

> **What:** scoping document for a custom maldev packer.
> **Status:** design only. No code shipped.
> **Tracking:** P3.1 in [`backlog-2026-04-29.md`](backlog-2026-04-29.md).

## Why a custom packer?

`pe/morph` already mutates UPX section names so off-the-shelf
unpackers fail to recognise the input. `pe/strip` removes Go
toolchain markers (pclntab, runtime symbols). `pe/srdi` (Donut)
wraps PEs into PIC shellcode for in-memory execution. Each
solves one specific problem.

The gap: a **single PE on disk** that defeats both static
signature engines AND naive unpacker tooling, while still
loading natively (no Donut shellcode wrapper, no `inject/*`
plumbing on the consumer side). Today's options are:

| Option | Defeats static AV? | Defeats unpackers? | Loads as native PE? | Comment |
|---|---|---|---|---|
| Plain UPX | ❌ (signature on stub) | ❌ | ✓ | Industry baseline; flagged immediately |
| `pe/morph` UPX rename | ✓ (off-the-shelf) | partial (manual unpack still works) | ✓ | Cheapest cover; defenders catch the unpack pattern eventually |
| `pe/srdi` (Donut) | partial (Donut stub has signature) | n/a (not a PE on disk) | ❌ — needs `inject/*` | Strong in-memory cover; on-disk artefact is shellcode |
| `pe/strip` + `pe/morph` + `pe/cert` graft | strong | n/a (no compression layer) | ✓ | No size reduction; static surface still has visible code regions |
| **`pe/packer` (this proposal)** | strong | strong | ✓ | Closes the on-disk gap |

`pe/packer` is for the case where the operator wants ONE `.exe`
to drop on disk that:

1. Looks unrecognisable to AV signature scans.
2. Doesn't unpack cleanly with PEiD / x64dbg's UPX plugin /
   IDA's UPX preprocessor.
3. Loads + runs natively (target double-clicks → payload runs;
   no extra shellcode runtime).
4. Compresses to reduce final binary size (the original
   reason packers exist; we want this benefit too, not just
   the cover).

## Threat model

| Defender | What they do | Packer's answer |
|---|---|---|
| **Static AV signatures** (Defender, Sophos, ClamAV, YARA-rule farms) | Hash + byte-pattern match on the on-disk file | Encrypted-section payload + polymorphic stub. Stub bytes differ per pack. |
| **Off-the-shelf unpackers** (PEiD, CFF Explorer, x64dbg's UPX plugin, IDA preprocessors) | Detect known packer signatures (UPX/MPRESS/Themida headers), auto-unpack | No matchable header. Stub doesn't advertise itself. |
| **Manual reverse engineers with x64dbg/IDA** | Set breakpoint at OEP, dump unpacked memory | Anti-debug in stub (opt-in) refuses to unpack under debug; junk sections + fake imports slow analysis but don't defeat it. RE will get through eventually. |
| **EDR memory scanners** (Defender ATP, MDE, CrowdStrike) | Scan committed pages mid-execution | OUT OF SCOPE for `pe/packer`. The unpacked payload sits in memory like any unpacked binary — pair with `evasion/sleepmask` + `evasion/preset` for that surface. |
| **Behavioural EDRs** (`PsSetCreateProcessNotify`, ETW kernel-mode) | Watch for "freshly-created process allocates RWX" | Stub silences AMSI/ETW BEFORE decrypt (opt-in, ~1 KB). For full coverage pair with `evasion/preset.Stealth`. |
| **Sandbox unpackers** (Cuckoo Stage 2, FireEye memory dumps) | Run the packed binary, dump unpacked region from memory | Out of scope — by definition the unpacker has unpacked. Combine with `recon/sandbox` for early-bail, NOT packer-level evasion. |

Explicitly **NOT** in scope:
- In-memory anti-scan (sleepmask's job).
- Authenticode signing of the packed PE itself (`pe/cert.SignPE`'s
  job; opt-in graft AFTER pack is the integration).
- Identity masquerading (`pe/masquerade`'s job; can be applied
  to the host PE before pack).
- AMSI / ETW patching of the host process (`evasion/preset`'s
  job — packer's stub does silencing during unpack only).

`pe/packer` solves ONE problem: the on-disk byte pattern of
the bundled payload.

## Hard constraints (from design discussion)

These came out of brainstorming and are non-negotiable for v1:

1. **Pure Go toolchain only.** No mingw, no TinyGo, no nasm,
   no CGO. Operator's build host has `go build`, nothing else.
   Implication: stub is either pure Go source or hand-rolled
   Go-asm `.s` files. Decision: **pure Go source** (Q13).
   Stub size budget revised from "10 KB" to "~500 KB" — the
   Go runtime cost. Acceptable because most maldev implants
   already carry the Go runtime; packed output stays in the
   1-2 MB range comparable to UPX-packed Go binaries.

2. **Polymorphism via compile-time templating** (Q14). Each
   `Pack()` invocation generates a fresh stub source with
   randomised variable names + struct ordering + junk code,
   invokes `go build` at pack-time, embeds the result.
   Implication: `Pack()` requires `go build` on the host
   running it (operator's build box, not the implant). Each
   packed binary has unique stub bytes — defeats hash-based
   batch detection.

3. **Library + CLI surface** (Q15). `pe/packer.Pack(bytes)`
   for Go-pipeline integration; `cmd/packer` thin CLI wrapper
   for standalone ops.

4. **Cross-platform** (Q9). Windows PE pack + Linux ELF pack.
   Same `Pack()` API; backend dispatches on input format.

## Capability matrix

Every capability ships as an **option** so operators dial in
size vs cover per-engagement (per Q1, Q7, Q8, Q10, Q11, Q12 —
"all of the above as options"):

| Capability | Default | Option | Cost (size / time) |
|---|---|---|---|
| **Cipher** (Phase 1) | AES-GCM | XChaCha20-Poly1305, RC4 (legacy) | minimal |
| **Compressor** (Phase 1) | aPLib (small decoder) | LZMA (best ratio), zstd, custom LZ4 (tiny) | decoder size 0.5-20 KB |
| **Key location** (Phase 1) | embedded | host-fingerprint-derived, external (config / network) | minimal / breaks portability / network footprint |
| **Anti-debug** (Phase 1, opt-in) | off | `IsDebuggerPresent` + `ProcessDebugPort` + RDTSC delta + `ThreadHideFromDebugger` | ~500 bytes, ~µs at unpack |
| **AMSI/ETW silence** (Phase 1, opt-in) | off | stub patches AMSI + ETW before decrypt | ~1 KB, mandatory if AMSI v2 in scope |
| **Cert graft** (Phase 1, opt-in) | off | call `pe/cert.SignPE` on the packed output | inherits SignPE limitations |
| **Multi-target bundle** (Phase 1, opt-in) | off | N encrypted payloads in one PE; stub fingerprints + selects | linear in payload count |
| **Section shuffle** (Phase 2) | on | randomise host PE section order; insert zero-byte separators | minimal |
| **IAT scramble** (Phase 2) | on | replace plaintext API names with hash-resolved imports (PEB walk + ROR13) | small; stub gains a resolver |
| **Junk sections + fake imports** (Phase 3) | on | high-entropy filler + benign-DLL fake imports | adds 5-50 KB depending on knob |
| **Stub control-flow obfuscation** (Phase 3) | off | flatten + opaque predicates in the stub itself | doubles stub size, slows unpack |

## Hard NO

- VM-based obfuscation (Themida / VMProtect style). Way too
  heavy for maldev's "operator can ship in one Go build" ethos.
- Recursive packing (`pack(pack(input))`). Each layer adds
  visible entropy + decompressor footprint. Diminishing
  returns; explicitly forbidden.
- Server-side decryption-key fetch as DEFAULT. Network
  footprint is too loud. Available as an opt-in
  Q1-external mode for use cases that genuinely need it.

## Cross-platform plan (Q9)

| Platform | Input format | Output format | Stub language |
|---|---|---|---|
| Windows | PE32+ | PE32+ | pure Go + `golang.org/x/sys/windows` |
| Linux | ELF64 | ELF64 | pure Go + `golang.org/x/sys/unix` + `mmap` syscall |

Same `pe/packer.Pack(bytes []byte) ([]byte, error)` API. Backend
sniffs `MZ`/`\x7fELF` magic and dispatches to the right pipeline.
Each platform has its own stub (different reflective loader),
randomised independently per pack.

## Phases

### Phase 1 — encrypted-payload + reflective stub

**Scope:**
- Compress + encrypt original PE/ELF with `crypto/` AEAD.
- Embed the encrypted blob as a custom `.maldev` (PE) /
  `.note.maldev` (ELF) section in a freshly-built host binary.
- Pure-Go reflective loader stub generated per-pack:
  locates own packed section → decrypts → decompresses →
  reflectively loads (parse PE/ELF, allocate, copy sections,
  fixup IAT/relocations, jump to OEP).
- Polymorphic generation via compile-time templating
  (per Q14): each `Pack()` produces a stub with unique
  variable names, struct field ordering, junk-code insertion
  patterns, and randomised constants.

**Constraints:**
- Stub is pure Go (Q13). Size budget ~500 KB; goal is
  unique-bytes-per-pack, not minimum size.
- Reflective load must NOT call any Win32/POSIX path that
  requires plaintext API names (use ROR13 PEB walk on
  Windows; `dlsym` via direct syscall on Linux).
- Pack-time requires `go build` available (Q14) — operator
  ships from a build host, never from the implant.

**Sample API surface:**
```go
type Cipher int
const (
    CipherAESGCM Cipher = iota
    CipherChaCha20
    CipherRC4
)

type Compressor int
const (
    CompressorAPLib Compressor = iota
    CompressorLZMA
    CompressorZstd
    CompressorLZ4
)

type KeyMode int
const (
    KeyEmbedded KeyMode = iota
    KeyHostFingerprint
    KeyExternal
)

type Options struct {
    Cipher       Cipher        // default CipherAESGCM
    Compressor   Compressor    // default CompressorAPLib
    KeyMode      KeyMode       // default KeyEmbedded
    Key          []byte        // generated if nil

    AntiDebug      bool        // default false; opt-in (Q8)
    SilenceAMSIETW bool        // default false; opt-in (Q12)
    GraftCert      *cert.SignOptions // default nil; opt-in (Q10)
    MultiTarget    []TargetPayload   // default nil; opt-in (Q11)
}

func Pack(in []byte, opts Options) (out []byte, key []byte, err error)
func Unpack(packed []byte, key []byte) (orig []byte, err error)  // for tests
```

**Tests (host-only — no VM dependency):**
- Round-trip: pack(notepad.exe) → run → notepad opens.
- Round-trip on corrupted ciphertext → stub fails cleanly
  (not crash).
- Round-trip across `Cipher` / `Compressor` choices.
- Polymorphism: pack(same input) twice → output bytes differ
  in stub region; payload region differs by IV.
- Cross-platform: pack(elf64) on Linux → linux/amd64 binary
  runs.

### Phase 2 — section shuffle + IAT scramble

**Scope:**
- Randomise host PE section order. Adjusts file offsets,
  RVAs, optional-header `SizeOfImage` / `SizeOfHeaders` /
  `BaseOfCode`. Never touch `.maldev` placement (stub must
  reach it).
- Replace import directory entries with hash-resolved imports
  (the stub reconstructs the IAT at runtime via PEB walk +
  ROR13). Removes plaintext API names from the on-disk file.
- Optional: insert a randomised number of zero-byte separator
  sections to push offsets around.

**Constraints:**
- Loader must still accept the PE (Windows is permissive on
  section ordering but rejects misaligned offsets / size
  overflows).
- IAT scrambling means the stub MUST resolve everything it
  needs WITHOUT looking it up by name. Plumbing reuse: same
  trick `runtime/bof` uses today.

### Phase 3 — anti-static-RE cover

**Scope:**
- Fill junk sections with high-entropy random bytes so simple
  "this section looks too uniform" heuristics misfire.
- Add fake imports to legitimate-looking but unused DLLs
  (gdi32, comdlg32) so the import table looks normal-ish to
  a human glancing at it.
- Optional: code obfuscation in the stub itself (control-flow
  flattening, constant unfolding) so the stub doesn't look
  identical across multiple packed binaries — synergistic
  with Phase 1's per-pack templating.

**Constraints:**
- Fake imports must NOT be called at runtime — decoration only.
- Stub obfuscation costs CPU at unpack time + doubles stub
  size; opt-in.

## Industry survey (2026-05-06)

Inspected 6 public packers to lift good ideas + avoid known
pitfalls. Findings drive the revised phase plan below.

| Repo | Killer feature(s) absorbed |
|---|---|
| [EgeBalci/amber](https://github.com/EgeBalci/amber) | SGN multi-pass encoder (`-e N`); PE header scrape (drop MZ+DOS stub); CRC32 + IAT API resolver alternatives; reflective payload self-erase post-load |
| [phra/PEzor](https://github.com/phra/PEzor) | Memory fluctuation RX↔RW/NA during sleep (already covered by `evasion/sleepmask`); environmental keying (`GetComputerNameExA` XOR key); 9 output formats (exe / dll / reflective-dll / service-exe / service-dll / dotnet / bof / dotnet-pinvoke / dotnet-createsection); DLL-sideload generation; sleep-before-unpack; SGN integration; anti-debug + unhook opt-ins |
| [rtecCyberSec/Packer_Development](https://github.com/rtecCyberSec/Packer_Development) | x33fcon 2024 workshop — explicitly addresses entropy-based detection + sandbox evasion; modular `encrypt` / `antidebug` / `sandbox` (Delay + DomainJoin keying) / `AMSIETWBypass` / `peload` / `shellcodeexecute` / `assemblyLoad` / `dll` |
| [Unknow101/FuckThatPacker](https://github.com/Unknow101/FuckThatPacker) | Naive XOR + Base64 + UTF16-LE for AMSI bypass (limited useful patterns) |
| [czs108/Windows-PE-Packer](https://github.com/czs108/Windows-PE-Packer) | "Shell entry" concept (educational); import-table runtime transformation; section name clearing — aligns with our Phase 2 |
| [pmq20/ruby-packer](https://github.com/pmq20/ruby-packer) | Different domain (Ruby app packing via SquashFS); not directly transferable |

## Composability + anti-entropy (2026-05-06 user requirements)

User explicitly asked for two capabilities the original Phase 1
plan didn't surface:

### Composability — pipeline of multiple ciphers

`Options.Cipher` (single value) is too narrow. Operators want
to STACK ciphers + permutations + compression:

```go
opts.Pipeline = []packer.PipelineStep{
    {Op: packer.OpCompress,   Algo: packer.CompressorAPLib},
    {Op: packer.OpPermute,    Algo: packer.PermutationSBox},
    {Op: packer.OpCipher,     Algo: packer.CipherAESGCM},
}
```

Pack runs the pipeline forward; Unpack runs it reverse. Each
step is one of:

- `OpCipher` — any of the AEADs / stream ciphers in `crypto/`
- `OpPermute` — S-Box / Matrix Hill / ArithShift / XOR (existing in `crypto/`)
- `OpCompress` — aPLib (default) / LZMA / zstd / LZ4
- `OpEntropyMask` — see below

Ships in Phase 1c.

### Anti-entropy techniques

High entropy (~7.5+ bits/byte) is one of the most reliable AV
signals. Five industrial techniques surveyed:

| # | Technique | Apparent entropy | Size cost | CPU cost | Phase |
|---|---|---|---|---|---|
| 1 | **XOR mask with code-like bytes** (low-entropy mask matches `.text` profile) | ~4-5 bits/byte | 0% | µs | 1d |
| 2 | **Carrier resource embedding** — ship blob inside `.rsrc` PNG/JPEG-shaped wrapper | hidden behind expected high-entropy resource | +5-10% PNG header | low | 1d |
| 3 | Steganographic LSB (4× expansion) | follows carrier | 4× | medium | NOT shipped — too costly |
| 4 | **Interleaved low-entropy padding** (insert runs of zeros / ASCII / fake-strings between ciphertext chunks) | sectional alternation | +20-50% | minimal | 1d |
| 5 | ASCII-output encoding (Base64 + dictionary) | ~5 bits/byte | +33% (Base64) | low | NOT shipped — Base64 trips other heuristics |

Ship #1 + #2 + #4 in Phase 1d as `Options.EntropyCover`.

## Revised phase plan

| Phase | Scope | Status |
|---|---|---|
| 1a | encrypt + embed pipeline (AES-GCM + blob format) | ✅ v0.50.0 |
| 1b | Windows reflective loader stub | ✅ v0.51.0 |
| **1c** | **Composability pipeline** — `Options.Pipeline []PipelineStep` + integration with `crypto/*` (cipher, permutation). | ⏳ next |
| 1c.5 | Compression in pipeline — aPLib (smallest decoder, ~500 bytes) ships first, then LZMA / zstd / LZ4 as opt-in | ⏳ |
| 1d | Anti-entropy — XOR mask + carrier resource + interleaved padding, all opt-in via `Options.EntropyCover` | ⏳ |
| 1e | Polymorphic stub generation (compile-time templating) + multi-format output (exe / reflective-dll / service-exe / dotnet / bof) | ⏳ |
| 1f | Linux ELF reflective loader (mirror Phase 1b) + remaining opt-ins (anti-debug / AMSI silence / cert graft / multi-target / env keying — host fingerprint / domain join / date range) | ⏳ |
| 2 | Section shuffle + IAT scramble (host PE) | deferred |
| 3 | Junk sections + stub control-flow obfuscation | deferred |

## Tracking

- P3.1 row 1 (this doc) — closes with this commit.
- P3.1 row 2 (Phase 1 build) — separate ship; depends on this
  scope being agreed.
- P3.1 row 3 (Phase 2) — separate ship; depends on Phase 1.
- P3.1 row 4 (Phase 3) — separate ship; depends on Phase 2.

## See also

- [`pe/morph`](../techniques/pe/morph.md) — UPX rename
  (adjacent technique; both ship, different problems).
- [`pe/srdi`](../techniques/pe/pe-to-shellcode.md) — Donut
  shellcode (alternative path; packer is "Donut for PEs on
  disk").
- [`pe/cert`](../techniques/pe/certificate-theft.md) —
  Authenticode graft (opt-in post-pack via `GraftCert` option).
- [`crypto`](../techniques/crypto/payload-encryption.md) —
  AEAD layer for Phase 1.
- [`evasion/sleepmask`](../techniques/evasion/sleep-mask.md) —
  in-memory cover (orthogonal — packer hides on disk, sleepmask
  hides in memory).
- [`runtime/bof`](../techniques/runtime/bof-loader.md) — same
  PEB-walk + ROR13 dynamic-resolution pattern Phase 2 IAT
  scramble will reuse.
