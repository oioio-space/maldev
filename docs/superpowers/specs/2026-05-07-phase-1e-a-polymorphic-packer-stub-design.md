---
last_reviewed: 2026-05-07
reflects_commit: b9554ed
status: draft
---

# Phase 1e-A — Polymorphic packer stub (pure-Go SGN-style amd64)

> Design spec locking scope, architecture, components, contracts, and tests
> for the first multi-format milestone of the maldev packer. Phase 1e-A
> ships **end-to-end runnable Windows PE output** with **per-pack
> polymorphic stage-1 decoder** and **zero pack-time toolchain
> dependency**.
>
> Brainstorming session 2026-05-07 — every choice below is the
> "best, no-laziness, project-philosophy" answer from a multi-question
> dialogue. The full Q→A trail is captured in "Decisions Locked"
> below for future-self reference.

## Summary

| Item | Choice |
|---|---|
| Phase 1e scope | **Decompose into stages like 1f.** 1e-A: Windows EXE host with polymorphic stage-1. ELF / DLL / BOF / dotnet defer to 1e-B/C/D/E. |
| Polymorphism mechanism | **Pure-Go re-implementation of SGN's metamorphic algorithm** using `github.com/twitchyliquid64/golang-asm` as the amd64 encoder backend. Pack-time generates fresh stage-1 bytes per call. |
| Pack-time toolchain | **None.** No `go build`, no system linker, no nasm/keystone/CGO. The packer stays a pure library. |
| Architecture | **Two-stage.** Stage 1 = small SGN-encoded amd64 decoder loop (~50-150 instructions). Stage 2 = unchanged existing `pe/packer/runtime` Go EXE shipped pre-built and committed as a stub variant. Stage 1 decrypts stage 2 + payload at runtime, JMPs into stage 2's entry. |
| Stage-2 polymorphism | **Patch table** — pre-built Go EXE with sentinel byte ranges that the packer rewrites per call (BuildID, embedded payload offset, etc.). Augments stage-1's polymorphism with byte-level uniqueness on stage 2. |
| Encrypted-blob format | Custom `.maldev` PE section, optionally wrapped in PNG/JPEG carrier (Phase 1d composition). |
| Per-pack uniqueness target | Hamming distance > 70% across two packs of the same payload. Defeats hash-batch and signature-byte AV. |

## Decisions locked

The brainstorm explored seven design axes. Each was answered with the
project-philosophy lens ("pure Go, no CGO, no external toolchain,
operator ships from one `go build`").

1. **Phase 1e scope** — Stage-decomposed (Z), not big-bang.
2. **Polymorphism mechanism** — SGN-algorithm in pure Go (E), not
   compile-time templating (A1) which would need `go build` at pack-time.
3. **Encoder backend** — `golang-asm` (BSD-3, mature, Plan 9 syntax
   matches existing `.s` files in the repo). NOT writing our own encoder
   from scratch — `golang-asm` solves a 600-LOC sub-problem with zero
   maintenance burden.
4. **Polymorphism algorithm** — SGN's metamorphic engine (Ege Balci 2018
   paper). Instruction substitution + register reassignment + junk
   insertion + N-round iteration. Re-implemented from the published
   algorithm, NOT importing `EgeBalci/sgn` (which transitively requires
   `keystone-go` which is CGO — violates the project Hard NO).
5. **Stage-2 strategy** — Pre-built Go EXE committed as stub variant +
   patch table. Avoids `go build` at pack-time while preserving the
   ability to swap stub variants without code changes.
6. **Format scope** — `FormatWindowsExe` only in 1e-A. ELF host (1e-B),
   DLL host (1e-C), BOF (1e-D), dotnet (1e-E) staged separately.
7. **Stub-output byte format** — Custom `.maldev` section in the host PE
   per `packer-design.md`. Optional carrier wrap composes with Phase 1d's
   `EntropyCoverCarrier`.

Three rejected alternatives worth tracking:

- **Donut-only wrapping** (Approach C): rejected because Donut's stub
  bytes are signatured by enterprise AVs (Defender ATP, MDE, CrowdStrike).
  We retain `pe/srdi`'s Donut integration for the cases where it IS the
  right tool (PE→shellcode for `inject/*` paths), but it's not
  appropriate for end-to-end packed-binary output.
- **Compile-time templating + `go build`** (Approach A1): rejected
  because it breaks pure-library mode (Pack now spawns a child process).
  The user explicitly required "no go build wrapper" — this codifies that.
- **Hand-rolled custom polymorphism** (Approach A): rejected in favor of
  E because SGN is a 15-year-refined algorithm with proven AV-evasion
  characteristics. Re-implementing its design beats inventing our own.

## Architecture

### Acceptance contract

`PackBinary(payload []byte, opts PackBinaryOptions)` accepts:

- `payload` — arbitrary bytes (typically a target PE EXE the operator
  wants to deploy). Phase 1c+ pipeline handles cipher / compression /
  entropy-cover upstream; PackBinary takes the raw payload and runs
  PackPipeline + the new stage-1 wrapping in one call.
- `opts.Format = FormatWindowsExe` (only value supported in 1e-A).
- `opts.Stage1Rounds` — number of SGN encoding rounds (default 3,
  range 1..10). Higher = more polymorphism + larger stage-1 + more
  decode time.
- `opts.Pipeline` — existing PipelineSteps for the inner-payload
  encryption (cipher / permute / compress / entropy-cover).
- `opts.Seed` — deterministic seed for reproducible packs (testing).
  Zero (default) draws from `crypto/rand`.

### Output contract

Returns `(host []byte, key []byte, err error)`:

- `host` — a complete Windows PE32+ executable. When written to disk
  and run, it self-decrypts via stage 1, reads its embedded encrypted
  payload, and reflectively loads the original payload via the
  unchanged `pe/packer/runtime` pipeline.
- `key` — the AEAD key for the user's payload (same as the existing
  `Pack` API). Operators transport it out-of-band.
- `err` — wrapped sentinel describing the failure mode (see Error
  handling section).

### Two-stage runtime flow

```
PE entry
   │
   ▼
[stage 1: SGN-encoded asm decoder loop, fresh bytes per pack]
   • round N peels XOR layer N → encoded[N-1]
   • round N-1 peels layer N-1 → encoded[N-2]
   • …
   • round 1 peels layer 1 → stage2_bytes || encryptedPayload
   • JMP into stage2_bytes entry (RIP-relative)
   ▼
[stage 2: pre-built Go EXE with pe/packer/runtime baked in]
   • locates encryptedPayload via sentinel byte sequence
   • calls runtime.LoadPE(encryptedPayload, embeddedKey)
   • JMP to original payload OEP
   ▼
[original payload runs]
```

### File layout

```
pe/packer/
├── packer.go                           # +PackBinary entry
└── stubgen/                            # NEW package tree
    ├── doc.go                          # package overview
    ├── stubgen.go                      # public Generate() — orchestration
    ├── amd64/
    │   ├── doc.go
    │   ├── builder.go                  # golang-asm builder wrapper
    │   ├── operands.go                 # Reg, Imm, MemOp, LabelRef
    │   └── builder_test.go             # encoder cross-check vs x86asm.Decode
    ├── poly/
    │   ├── doc.go
    │   ├── substitution.go             # SGN equivalence-preserving rewrites
    │   ├── regalloc.go                 # randomized register pool
    │   ├── junk.go                     # NOP variants + dead-op insertion
    │   ├── engine.go                   # N-round Encode driver
    │   └── poly_test.go                # round-trip + uniqueness tests
    ├── stage1/
    │   ├── doc.go
    │   ├── round.go                    # one decoder loop emission
    │   └── round_test.go               # Go-side reference decoder cross-check
    ├── host/
    │   ├── doc.go
    │   ├── pe.go                       # minimal PE32+ emitter
    │   └── pe_test.go                  # debug/pe parse-back validation
    └── stubvariants/                   # pre-built stage-2 binaries committed
        ├── README.md                   # rebuild instructions for maintainers
        ├── stage2_v01.exe              # ~800 KB stripped Go runtime stub
        ├── stage2_v02.exe              # 4-8 variants total
        └── …
```

### `PackBinary` signature

```go
type Format uint8

const (
    FormatUnknown Format = iota
    FormatWindowsExe
    // FormatLinuxELF, FormatWindowsDLL, FormatBOF — Phase 1e-B+
)

type PackBinaryOptions struct {
    Format       Format         // FormatWindowsExe in 1e-A
    Pipeline     []PipelineStep // existing Phase 1c+ pipeline for inner payload
    Stage1Rounds int            // SGN rounds; default 3
    Key          []byte         // payload AEAD key; generated if nil
    Seed         int64          // poly seed; 0 = crypto-random
}

// PackBinary takes a raw payload and produces a runnable host
// binary with polymorphic stage-1 decoder + reflective stage-2.
// Pure Go: no go build, no system toolchain at pack-time.
//
// Sentinels: ErrUnsupportedFormat, ErrInvalidRounds,
// ErrPayloadTooLarge, ErrEncodingSelfTestFailed.
func PackBinary(payload []byte, opts PackBinaryOptions) (host []byte, key []byte, err error)
```

## Components

### `stubgen/amd64/` — encoder backend

Wraps `golang-asm`'s obj.Prog API into a builder pattern. Hides the
linker-context plumbing behind a focused subset of mnemonics actually
used by stage-1.

```go
type Builder struct{ /* obj.Prog list + label table + golang-asm linker */ }

func New() *Builder

// Operand-typed instruction emitters. Each returns *Inst so the
// caller can attach labels or post-emission notes.
func (b *Builder) MOV(dst, src Op) *Inst
func (b *Builder) LEA(dst Reg, src MemOp) *Inst
func (b *Builder) XOR(dst, src Op) *Inst
func (b *Builder) SUB(dst, src Op) *Inst
func (b *Builder) ADD(dst, src Op) *Inst
func (b *Builder) JMP(target Op) *Inst
func (b *Builder) JNZ(target Op) *Inst
func (b *Builder) DEC(dst Op) *Inst
func (b *Builder) CALL(target Op) *Inst
func (b *Builder) RET() *Inst
func (b *Builder) NOP(width int) *Inst    // 1..9-byte NOP variants per Intel SDM
func (b *Builder) Label(name string) *Inst

// Encode walks the prog list, resolves labels, and produces
// machine bytes. Errors propagate from golang-asm's lowering pass.
func (b *Builder) Encode() ([]byte, error)
```

Operand types:

```go
type Op interface { isOp() }

type Reg uint8 // RAX..R15 (no RSP/RBP — they're reserved for stack)
type Imm int64 // sign-extended where width permits
type MemOp struct {
    Base, Index Reg     // Index zero = no SIB
    Scale       uint8   // 1, 2, 4, 8
    Disp        int32
    RIPRelative bool    // when Base == 0xFF
    Label       string  // when RIPRelative + Label != "" — resolved by Encode
}
type LabelRef string
```

### `stubgen/poly/` — SGN metamorphic engine

```go
// substitution.go — equivalence-preserving rewrites for "set reg = reg ^ key"
type Subst func(b *amd64.Builder, dst Reg, key uint64)

var XorSubsts = []Subst{
    func(b, d, k) { b.XOR(d, Imm(int64(k))) },                       // canonical
    func(b, d, k) { b.SUB(d, Imm(int64(neg(k)))) },                  // SGN classic
    func(b, d, k) { b.ADD(d, Imm(int64(complement(k)+1))) },         // SGN classic
    // 4-6 variants total; engine picks one per round
}

// regalloc.go
type RegPool struct{ /* shuffled []Reg without RSP/RBP */ }
func NewRegPool(seed int64) *RegPool
func (p *RegPool) Take() Reg
func (p *RegPool) Release(r Reg)

// junk.go
func InsertJunk(b *amd64.Builder, density float64, regs *RegPool, rng *rand.Rand)
// NOP variants (1-9 bytes), XOR reg-self (zeroes a scratch), push/pop,
// and opaque-true conditional jumps that dead-end into next instruction.

// engine.go
type Engine struct {
    rng    *rand.Rand
    rounds int
}

func NewEngine(seed int64, rounds int) *Engine

// Encode wraps `payload` in N rounds of polymorphic XOR. Returns
// (encodedPayload, stage1Asm). The encoder picks fresh keys, fresh
// substitutions, fresh register assignments, and fresh junk per
// round.
func (e *Engine) Encode(payload []byte) (encoded []byte, stage1 []byte, err error)

// EncodeRound runs one SGN round. Exposed for tests.
func (e *Engine) EncodeRound(payload []byte, round int) (encoded []byte, decoder []byte, err error)
```

### `stubgen/stage1/` — decoder-loop IR

```go
type Round struct {
    Key       []byte
    Subst     poly.Subst       // chosen XOR variant for this round
    KeyReg    Reg              // randomized
    ByteReg   Reg              // randomized (8-bit subset of a 64-bit reg)
    SrcReg    Reg              // pointer into encoded data
    CntReg    Reg              // remaining-bytes counter
    JunkAfter int              // junk bytes inserted after each instruction
}

// Emit writes one decoder loop to the builder. The loop reads
// payloadOff bytes (computed RIP-relative), XORs each by Key with
// Subst variant, writes back, decrements counter, branches if not
// zero. Final JMP target is set by the engine's chain assembly.
func (r *Round) Emit(b *amd64.Builder, payloadOff int, payloadLen int)
```

Multi-round chain layout in the emitted asm:

```
decoder_round_3_entry:
  MOV cnt = payloadLen
  LEA src = [rip + payload_offset]
  loop_3:
    MOV byte_reg = byte ptr [src]
    [poly.Subst applied to byte_reg with key_3]
    MOV byte ptr [src] = byte_reg
    INC src
    DEC cnt
    JNZ loop_3
  ; (encoded data after this round = round 2's input)
  ; fall through to decoder_round_2_entry

decoder_round_2_entry:
  ; … same shape with key_2, freshly randomized regs and substs

decoder_round_1_entry:
  ; … same shape with key_1

  ; Final jump into the now-decoded stage 2:
  JMP [rip + payload_offset + stage2_entry_offset]
```

### `stubgen/host/` — minimal PE32+ emitter

Hand-emits a minimal Windows PE32+ executable:

```go
type PEConfig struct {
    Stage1Bytes []byte           // emitted asm — goes into .text
    PayloadBlob []byte           // encoded stage 2 || encrypted payload
    AddCarrier  bool             // wrap PayloadBlob in PNG header (Phase 1d compose)
    Subsystem   uint16           // IMAGE_SUBSYSTEM_WINDOWS_CUI/GUI; default CUI
}

func EmitPE(cfg PEConfig) ([]byte, error)
```

Layout:

```
DOS Header (64 bytes, randomized stub padding bytes)
PE Signature ("PE\0\0")
COFF File Header (Machine = 0x8664, NumberOfSections = 2 or 3)
Optional Header PE32+ (Magic = 0x20B, AddressOfEntryPoint = stage1 RVA,
                        ImageBase = 0x140000000, SectionAlignment = 0x1000,
                        FileAlignment = 0x200, SubsystemVersion etc.)
Section Headers:
  .text   (RVA 0x1000, code, R+E, contains stage1Bytes)
  .maldev (RVA aligned, init data, R, contains PayloadBlob possibly carrier-wrapped)
  .rsrc   (optional, when AddCarrier — contains a tiny RT_VERSION resource for legitimacy)
Section Bodies (file-aligned)
```

Reference: Microsoft PE/COFF Specification revision 12.0.

### `stubgen/stubvariants/` — committed stage-2 binaries

Pre-built Go EXEs that embed `pe/packer/runtime`. Built by maldev
maintainers at release time, committed to the repo. Format:

- 4-8 variants (different `-trimpath` settings, different Go versions
  in the maintainer's pinned set, different junk-only source variants)
- Each variant: ~800 KB stripped (`-ldflags='-s -w' -gcflags='-l -B'`)
- Each carries a sentinel byte sequence at a known offset that the
  packer rewrites at pack-time to point at the embedded encrypted
  payload (patch-table style)
- README.md documents the build commands; CI smoke-tests rebuild
  reproducibility

Per-pack: `seed % len(variants)` picks one variant. Augments stage-1
polymorphism with stage-2 byte uniqueness.

### `pe/packer/packer.go` — `PackBinary`

```go
func PackBinary(payload []byte, opts PackBinaryOptions) (host []byte, key []byte, err error) {
    // 1. Validate options.
    if opts.Format != FormatWindowsExe {
        return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
    }
    if opts.Stage1Rounds < 1 || opts.Stage1Rounds > 10 {
        return nil, nil, fmt.Errorf("%w: rounds=%d", ErrInvalidRounds, opts.Stage1Rounds)
    }

    // 2. Generate or use payload AEAD key.
    if opts.Key == nil {
        opts.Key = mustRandKey()
    }
    key = opts.Key

    // 3. Encrypt payload via existing Phase 1c+ pipeline.
    encryptedPayload, _, err := PackPipeline(payload, opts.Pipeline)
    if err != nil { return nil, nil, fmt.Errorf("packer: pipeline: %w", err) }

    // 4. Pick a stage-2 variant (deterministic from seed).
    stage2 := stubgen.PickStage2Variant(opts.Seed)

    // 5. Patch stage-2 sentinel offsets to reference the encryptedPayload.
    inner := stubgen.PatchStage2(stage2, encryptedPayload, opts.Key)

    // 6. Run polymorphic stage-1 generation.
    host, err = stubgen.Generate(stubgen.Options{
        Stage2:       inner,
        Stage1Rounds: opts.Stage1Rounds,
        Seed:         opts.Seed,
        HostFormat:   opts.Format,
    })
    if err != nil { return nil, nil, fmt.Errorf("packer: stubgen: %w", err) }

    return host, key, nil
}
```

## Data flow

```
operator                                     PackBinary()
   │                                              │
   │  payload []byte, opts                        │
   ├─────────────────────────────────────────►    │
   │                                              ├─ existing PackPipeline → encryptedPayload
   │                                              ├─ pick stage2 variant from committed set
   │                                              ├─ patch stage2 sentinels → inner (= stage2 || encryptedPayload)
   │                                              ├─ stubgen.Generate(inner, rounds=3, seed):
   │                                              │     ↓
   │                                              │     poly.Engine.Encode(inner):
   │                                              │       round 3: encoded_3 = encode(inner, key_3, subst_3, regs_3, junk_3)
   │                                              │       round 2: encoded_2 = encode(encoded_3, key_2, subst_2, …)
   │                                              │       round 1: encoded_1 = encode(encoded_2, key_1, subst_1, …)
   │                                              │       stage1Asm = decoder_3 || decoder_2 || decoder_1 || JMP_to_decoded_entry
   │                                              │     ↓
   │                                              │     amd64.Builder.Encode() → stage1Bytes
   │                                              │     ↓
   │                                              │     host.EmitPE(stage1Bytes, encoded_1)
   │                                              │     ↓
   │                                              │     hostBytes
   │ ◄────────────────────────────────────────────┤
   │                                              │
   │  hostBytes []byte, key []byte                │

target executes hostBytes:
   PE entry → stage1Bytes
       decoder 3 peels round 3 of encoded_1 → encoded_2
       decoder 2 peels round 2 of encoded_2 → encoded_3
       decoder 1 peels round 1 of encoded_3 → inner (= stage2 || encryptedPayload)
       JMP into stage2 entry (RIP-relative, decoded location)
   stage2 runs:
       reads its own encryptedPayload via patched sentinel offset
       calls runtime.LoadPE(encryptedPayload, key)
       JMP to original payload OEP
```

## Error handling

| Surface | Sentinel | Wrapped message |
|---|---|---|
| Format unknown / not yet implemented | `ErrUnsupportedFormat` | "format %s not implemented; only FormatWindowsExe in Phase 1e-A" |
| Stage1Rounds out of bounds | `ErrInvalidRounds` | "Stage1Rounds must be 1..10, got %d" |
| Encoded payload exceeds size budget (default 100 MB) | `ErrPayloadTooLarge` | "encoded payload %d bytes exceeds budget %d" |
| `golang-asm` lowering fails | wrapped | "stubgen/amd64: encode: %w" |
| Round encoding self-test fails (Go-side reference decoder mismatch) | `ErrEncodingSelfTestFailed` | "round %d output failed decode self-test" |
| Stage-2 variant missing or corrupt | `ErrNoStage2Variant` | "stage-2 variant index %d missing" |
| Stage-2 sentinel offsets not found (patch-table mismatch) | `ErrStage2SentinelMissing` | "stage-2 variant %d missing payload sentinel" |
| PE emission produces malformed header | `ErrInvalidPEHeader` | wrapped from `host.EmitPE` |

**Pre-return self-test**: after `Generate` returns the host bytes, the
packer runs a Go-side reference decoder over the encoded blob (mirroring
stage-1's asm logic instruction-by-instruction). If the recovered bytes
don't match `inner`, the SGN encoding had a bug. Self-test fires before
returning to operator. Cost: O(rounds × payload_size) byte operations,
< 100ms for typical payloads.

## Testing strategy

### Unit tests (always run)

1. **`amd64.Builder` encoder cross-check** — for each supported instruction
   form (MOV / LEA / XOR / SUB / ADD / JMP / JNZ / DEC / CALL / RET / NOP)
   and each addressing mode (reg-reg, reg-imm32, reg-imm64, reg-mem,
   mem-reg, RIP-relative), emit via `amd64.Builder`, decode via
   `golang.org/x/arch/x86/x86asm.Decode`, assert mnemonic + operands match.
   ~200 LOC. Tests every instruction we actually use.

2. **`poly.Subst` equivalence** — for each substitution variant, emit it +
   emit the canonical `XOR reg, imm`, run a Go-side x86_64 register-state
   simulator over both, assert post-state identical for arbitrary inputs.
   The Go simulator is ~80 LOC and only covers the 11 instructions we use —
   acceptable scope.

3. **`poly.Engine.Encode` round-trip** — encode arbitrary bytes via Engine
   with N rounds, decode via Go-side reference decoder mirroring stage-1
   asm semantics, assert recovered = original. Run with N = 1, 3, 7, 10
   and seed = 0..50.

4. **`stubgen.Generate` per-pack uniqueness** — call twice with same input
   + Seed=1 vs Seed=2, assert Hamming distance between `.text` sections
   > 30%, between `.maldev` sections > 50%. Ditto with default
   crypto-random seed (statistical assertion over 16 calls).

5. **`host.EmitPE` validity** — emit, parse via `debug/pe.NewFile`, assert:
   - Section count correct (2 or 3 with carrier)
   - EntryPoint within `.text` section bounds
   - All section RVAs / file offsets aligned per OptionalHeader
   - No malformed Optional Header fields

6. **Stage-2 variant patch** — load each committed `stage2_vNN.exe`,
   verify the sentinel byte sequence is present at a stable offset,
   patch it with a known payload, re-load via `debug/pe.NewFile`, assert
   the patched binary still parses cleanly.

### E2E test (gated `maldev_packer_run_e2e`)

7. **`TestPackBinary_E2E_Linux_dryrun`** — Linux side: build hostBytes via
   `PackBinary(hello.exe)`, write to disk, parse the result with `debug/pe`,
   assert structural validity (we don't run it on Linux because it's
   Windows code).

8. **`TestPackBinary_E2E_Windows`** (Windows VM-gated, `cmd/vmtest`) — push
   hostBytes to a Windows VM, execute, capture stdout/stderr, assert
   "hello" appears. Same harness pattern as Phase 1f Stage C+D's E2E
   (subprocess re-spawn + assertion). Skipped without a working Windows VM.

### Cross-platform sanity

- `pe/packer/stubgen/...` files are cross-platform: pack-time runs on
  Linux/Mac/Windows, emits Windows PE bytes. No GOOS-specific imports.
- `GOOS=windows go build ./pe/packer/...` clean.
- `GOOS=darwin go build ./pe/packer/...` clean.

## Future work (out of scope for 1e-A)

- **1e-B — Linux ELF host** (mirror of 1e-A's Windows EXE for Linux
  static-PIE outputs). Reuses everything except the host emitter.
- **1e-C — Windows DLL host** (DLL sideload scenarios). Adds export
  table emission to `host`.
- **1e-D — BOF (Beacon Object File)** — single-section relocatable COFF
  for Cobalt Strike interop. Different host shape entirely.
- **1e-E — .NET assembly host** — CLR hosting; massive scope, defer.
- **Stage-1 advanced polymorphism** — control-flow flattening,
  opaque-predicate trees, shellcode-style position-independent loops
  with multi-stage indirect jumps. Adds 200-400 LOC; defer until empirical
  AV-evasion data justifies.
- **Anti-debug / AMSI silence opt-in** — already documented in
  `packer-design.md` Capability Matrix; wire into stage-2 Go runtime
  when an operator demand surfaces.

## See also

- `pe/packer/runtime/doc.go` — stage-2 reference implementation (existing).
- `pe/packer/runtime/runtime_linux_amd64.s` — existing Plan 9 asm in
  the repo; same assembly idiom we use here.
- `docs/refactor-2026-doc/packer-design.md` — capability matrix +
  industry survey (PEzor, amber, Donut, SGN). Phase 1e row updates on
  ship of 1e-A.
- `docs/refactor-2026-doc/HANDOFF-2026-05-06.md` — running cross-machine
  state; 1e-A entry added on commit.
- Ege Balci, *"Shikata Ga Nai (Encoder Still) Ain't Got Nothin' On Me!"*
  Black Hat USA 2018 — published SGN algorithm.
- `github.com/twitchyliquid64/golang-asm` — encoder backend.
- `golang.org/x/arch/x86/x86asm` — encoder cross-check decoder (test only).
- Microsoft PE/COFF Specification Revision 12.0 — host PE format reference.
