---
last_reviewed: 2026-05-07
reflects_commit: 8918cfc
status: draft
supersedes:
  - 2026-05-07-phase-1e-a-polymorphic-packer-stub-design.md
  - 2026-05-07-phase-1e-b-linux-elf-host-design.md
---

# Phase 1e UPX-style rewrite — in-place section encryption

> The Phase 1e-A and 1e-B architectures (host PE/ELF wrapper + stage 2
> Go EXE separately JMP'd into) shipped as v0.59.0 and v0.60.0 are
> structurally broken — see KNOWN-ISSUES-1e.md. This spec replaces both
> with a UPX-style architecture: the input PE/ELF is modified in
> place — `.text` is encrypted, a small polymorphic stub is appended
> as a new section, and the entry point is rewritten to the stub.
> The kernel handles loading normally; the stub only does the
> decrypt + JMP-to-OEP work.
>
> Brainstorming session 2026-05-07 — user directive: "regle le packer
> au mieux, sans donut, comme le ferait UPX mais avec nos spec".

## Why this rewrite

The broken architecture's three root causes:

1. `amd64.Builder.LEA` with `RIPRelative+Label` emits absolute SIB
   addressing, not RIP-relative. Decoder loop runs against NULL.
2. `stage1.Round.Emit` never emits a final JMP to stage 2.
3. Stage 2 = full Go EXE; its file-vs-image layout makes `JMP base + e_entry`
   land at the wrong bytes.

UPX-style architecture eliminates all three at the design level:

- **Bug 1 dies**: stub's data references are inside the SAME PE/ELF
  the stub lives in. CALL+POP+ADD computes the RVA delta — no LEA
  RIP-relative golang-asm encoding required.
- **Bug 2 dies**: stub's design includes the JMP-to-OEP from the start;
  the JMP target is the input binary's original entry point at its
  known RVA.
- **Bug 3 dies**: the kernel does the loading. The decrypted code
  is at the original `.text` RVA, where the kernel placed the section.
  No file-vs-image discrepancy.

UPX has been doing this since 1996. We follow the same architecture
with our own pure-Go pipeline (Phase 1c+ ciphers, polymorphic SGN
stage 1, anti-entropy carrier wrap).

## Summary

| Item | Choice |
|---|---|
| Architecture | UPX-style: modify input PE/ELF in place; encrypt `.text`; append small stub as new section; rewrite entry to stub. |
| Sections encrypted (v1) | **`.text` only** (Windows) / first PT_LOAD R+E segment (Linux). All other sections preserved. Future v2 can extend. |
| Stage 2 (separate Go EXE) | **Removed entirely.** Kernel handles loading; stub only decrypts + JMPs. |
| `pe/packer/runtime` package | **Kept available** for operators who want manual reflective loading in their own code. NOT used by `PackBinary`. |
| Stub model | Single polymorphic asm blob: CALL+POP+ADD prologue → N-round SGN decoder loops → JMP r15 to OEP. Per-pack fresh bytes. |
| Section addressing | RIP-relative computed at runtime via CALL+POP+ADD. No symbols, no linker, no post-Encode patch sentinels. |
| Permissions | `.text` section in modified binary marked **RWX** so stub can decrypt in place. New stub section R+E. Loud (AV may flag) — same trade-off UPX takes. |
| Stub size budget | 4 KiB pre-reserved (default). Empirically expected ~500-1500 B with 3 rounds + light junk. `ErrStubTooLarge` if exceeded. |
| Encryption | Existing Phase 1c+ pipeline (default AES-GCM single-step) on `.text` bytes. Output of pipeline = inner blob. SGN N-round wraps the inner blob; SGN decoder runs at runtime. |
| Polymorphism | SGN engine (existing `pe/packer/stubgen/poly`) — N-round XOR, register randomization, junk insertion, instruction substitution. |
| E2E test | Currently failing `pe/packer/packer_e2e_linux_test.go` is the regression contract. **Must pass after rewrite ships.** |

## Decisions locked

The brainstorm explored eight axes (A through H in the design space).
All locked per "le meilleur sans paresse, philosophie du projet":

A. **Per-section vs shared key**: shared. Smaller header, simpler stub.
B. **Stub size**: 4 KiB pre-reservation in the new section. Stub
   actual size measured at gen-time; `ErrStubTooLarge` if it overflows.
C. **Permissions**: `.text` RWX (no mprotect call needed). Loud,
   functional. UPX takes the same trade-off.
D. **Insertion point**: append a NEW section AFTER the last existing
   section. Doesn't shift any existing RVA. Computed
   `StubRVA = next page-aligned RVA past last section`.
E. **Sections encrypted**: `.text` only v1. Future v2 may extend to
   `.data` / `.rdata` after a careful audit of which sections the
   kernel reads at load (Import Directory, Resource Directory, Reloc
   Directory all stay plaintext).
F. **OEP**: original entry-point RVA recorded at pack-time, hard-coded
   into the emitted stub via the `(oepRVA - textRVA)` displacement.
G. **Polymorphism**: SGN per pack via `pe/packer/stubgen/poly` — kept
   unchanged from the broken architecture (the engine itself worked;
   the wiring around it didn't).
H. **Linux ELF**: same model — encrypt the R+E PT_LOAD's content,
   append new R+E PT_LOAD with the stub, rewrite `e_entry`.

## Architecture

### Acceptance contract

`PackBinary(input []byte, opts PackBinaryOptions)` accepts a
runnable input PE32+ (Windows) or ELF64 (Linux) with:

- A `.text` section (Windows) / first executable PT_LOAD (Linux)
- The original entry point (`AddressOfEntryPoint` / `e_entry`)
  inside that section
- No TLS callbacks (TLS callbacks run BEFORE the entry point and
  would touch encrypted code; out of scope v1)
- For PE: enough optional-header header room to add one section
  header (most real binaries have headroom; v1 fails loudly if not)

### Output contract

Returns `(modifiedBinary []byte, key []byte, err error)`:

- `modifiedBinary` — the input PE/ELF with these mutations:
  - `.text` section bytes replaced with `SGN_encode(PackPipeline(textBytes))`
  - `.text` section flags set to RWX (`MEM_READ|MEM_WRITE|MEM_EXECUTE`)
  - New section appended (name `.mldv`, R+E flags, contents = stub asm)
  - `AddressOfEntryPoint` (PE) / `e_entry` (ELF) rewritten to the new
    section's RVA
  - All other sections preserved byte-for-byte (Import Directory,
    Reloc Directory, Resources, Exception Directory, etc.)
- `key` — the AEAD key from `PackPipeline`. Operators transport
  out-of-band like in the existing `Pack` API.
- `err` — wrapped sentinel describing the failure mode.

### Runtime flow

```
target executes modifiedBinary
   │
   ▼
[kernel PE/ELF loader maps sections at their RVAs:
   - encrypted .text at TextRVA (RWX)
   - stub at StubRVA (R+E)
   - all other sections at their original RVAs (R, R+E, R+W, etc.)
 binds Import Directory normally, applies base relocs, JMPs to entry]
   │
   ▼ (entry = StubRVA)
[stub asm]
   CALL .next                  ; push RIP-of-next, fall through
.next:
   POP r15                     ; r15 = runtime address of .next
   ADD r15, (textRVA - .nextRVA) ; r15 = runtime address of .text start
   ; --- round N-1 decoder loop (peels outermost SGN layer) ---
   MOV cnt, textSize
   MOV key, k_{N-1}
   MOV src, r15
loopN-1:
   MOVZBQ (src), byte_reg
   <subst applied: byte_reg ^= k via subst.EmitDecoder>
   MOVB byte_reg, (src)
   ADD src, 1
   DEC cnt
   JNZ loopN-1
   ; --- round N-2 ---
   MOV src, r15                ; reset src
   ; ...same shape with k_{N-2}, fresh registers
   ; ...
   ; --- round 0 (peels innermost SGN layer; .text now plaintext) ---
   ;     after round 0 r15 still = .text base
   ; --- epilogue: JMP to OEP ---
   ADD r15, (oepRVA - textRVA)
   JMP r15
   ▼
[original code at OEP runs]
[Import Directory was bound by kernel — calls to LoadLibrary'd
 APIs work normally]
[exit_group / ExitProcess from the original payload kills the
 process — stub never returns]
```

### File layout

```
pe/packer/
├── packer.go                        # MODIFY: PackBinary drives transform/ pipeline
├── transform/                       # NEW — replaces stubgen/host/
│   ├── doc.go
│   ├── plan.go                      # Plan struct + format-agnostic helpers
│   ├── pe.go                        # PlanPE + InjectStubPE (Windows PE32+)
│   ├── pe_test.go
│   ├── elf.go                       # PlanELF + InjectStubELF (Linux ELF64)
│   └── elf_test.go
├── stubgen/
│   ├── amd64/                       # KEEP unchanged
│   ├── poly/                        # KEEP unchanged
│   ├── stage1/
│   │   ├── doc.go                   # MODIFY — describes new stub model
│   │   ├── stub.go                  # REPLACE round.go: EmitStub all-in-one
│   │   └── stub_test.go             # REPLACE round_test.go
│   ├── host/                        # DELETE entirely
│   ├── stubvariants/                # DELETE entirely
│   ├── doc.go                       # MODIFY — describe new generation flow
│   ├── stubgen.go                   # MODIFY — Generate drives Plan/Encrypt/Stub/Inject
│   └── stubgen_test.go              # ADJUST (drop EmitPE/EmitELF tests, add UPX-flow tests)
├── packer_e2e_linux_test.go         # KEEP — regression guard, must pass after rewrite
└── runtime/                         # KEEP unchanged. Operator-facing reflective loader.

cmd/packer/main.go                   # KEEP -format=windows-exe / linux-elf flags;
                                     # under the hood now calls into transform-driven flow.

docs/refactor-2026-doc/
├── KNOWN-ISSUES-1e.md               # KEEP — historical record of the gap
└── HANDOFF-2026-05-06.md            # MODIFY — banner becomes "fixed in v0.61.0"
```

## Components

### `pe/packer/transform/plan.go` (cross-platform)

```go
// Plan describes the layout transform.InjectStubPE/ELF will apply.
// Returned by PlanPE/PlanELF before stub generation so the stub
// emitter knows the RVAs it must reference.
//
// Two-phase design avoids the chicken-and-egg between "stub needs
// section RVAs" and "transform needs stub bytes":
//   1. PlanPE/ELF computes RVAs from input alone
//   2. Caller emits stub bytes using those RVAs (CALL+POP+ADD math
//      depends on textRVA - .nextRVA, both known once Plan is set)
//   3. InjectStubPE/ELF writes the emitted stub into the reserved
//      space, finalising the modified binary.
type Plan struct {
    TextRVA       uint32 // RVA of the section that gets encrypted
    TextFileOff   uint32 // file offset where encrypted bytes are written
    TextSize      uint32 // bytes to encrypt + decrypt at runtime
    OEPRVA        uint32 // original entry point — JMP target after decrypt
    StubRVA       uint32 // RVA of the new stub section (= new entry point)
    StubFileOff   uint32 // file offset where stub bytes are written
    StubMaxSize   uint32 // pre-reserved bytes for the stub
}

// Sentinels (cross-platform)
var (
    ErrUnsupportedInputFormat = errors.New("transform: unsupported input format")
    ErrNoTextSection           = errors.New("transform: input lacks a .text section")
    ErrOEPOutsideText          = errors.New("transform: original entry point is not within .text")
    ErrTLSCallbacks            = errors.New("transform: input has TLS callbacks (out of scope)")
    ErrStubTooLarge            = errors.New("transform: emitted stub exceeds reserved size")
    ErrSectionTableFull        = errors.New("transform: cannot append section header (no headroom)")
    ErrCorruptOutput           = errors.New("transform: modified binary failed self-test")
)
```

### `pe/packer/transform/pe.go` (Windows PE32+)

```go
// PlanPE inspects input PE bytes and computes the layout for the
// upcoming stub injection. Does NOT modify the input — the caller
// uses the returned Plan to drive stub generation, then calls
// InjectStubPE.
func PlanPE(input []byte, stubMaxSize uint32) (Plan, error)

// InjectStubPE applies the planned transform: encrypts .text in
// place (caller pre-encrypts and passes encryptedText), appends
// the stub section with the emitted stubBytes, rewrites the
// entry point. Pre-return self-test parses the output via
// debug/pe.NewFile and verifies invariants.
func InjectStubPE(input, encryptedText, stubBytes []byte, plan Plan) ([]byte, error)
```

Mechanics:

1. Read input headers via low-level byte parsing (similar to existing
   `pe/morph` / `pe/strip`). Don't use `debug/pe` — it's read-only and
   doesn't expose section-header-table slot positions.
2. For Windows the section header table lives at
   `e_lfanew + 24 + SizeOfOptionalHeader`. NumberOfSections from
   COFF header. Each section header is 40 bytes (`IMAGE_SECTION_HEADER`).
3. Compute new section's VirtualAddress = align_up(last_section_VA +
   last_section_VirtualSize, SectionAlignment).
4. Compute new section's PointerToRawData = align_up(last_section_PRD +
   last_section_SRD, FileAlignment).
5. Write new section header into the section table. Bump
   `NumberOfSections`. Update `SizeOfImage` to include the new section.
6. Update `AddressOfEntryPoint` = StubRVA.
7. Patch the existing `.text` section header's Characteristics to add
   `IMAGE_SCN_MEM_WRITE` (so the kernel maps it RWX).
8. Write encrypted .text bytes at `.text` PointerToRawData (overwriting
   the original code).
9. Append stub bytes at the new section's PointerToRawData (padded
   with zeros to FileAlignment).
10. Self-test: `debug/pe.NewFile(modified)` succeeds; entry point
    matches StubRVA; new section count == NumberOfSections.

### `pe/packer/transform/elf.go` (Linux ELF64)

Same shape, ELF mechanics:

1. Parse Ehdr + Phdr table.
2. Identify the PT_LOAD with PF_X flag (the executable segment).
   Could be one or many; v1 pick the FIRST PF_X PT_LOAD as `.text`
   equivalent.
3. The section table (e_shoff) is irrelevant at runtime — Linux uses
   PT_LOAD segments. We may rebuild or omit section headers.
4. Compute new PT_LOAD's vaddr = align_up(last_PT_LOAD_vaddr +
   last_PT_LOAD_memsz, p_align).
5. Add a new PT_LOAD with PF_R|PF_X for the stub. e_phnum++.
6. Modify the executable PT_LOAD's flags to add PF_W (RWX).
7. Write encrypted text bytes at the executable PT_LOAD's p_offset.
8. Write stub bytes at new PT_LOAD's p_offset.
9. Update `e_entry` = StubRVA.
10. Self-test: `debug/elf.NewFile(modified)` succeeds; entry within
    new PT_LOAD's vaddr range.

ELF caveat: bumping `e_phnum` requires PHysical headroom in the
header area. Most ELF outputs have at least one slot of slack;
when not, fail with `ErrSectionTableFull`. Future work: rewrite
the entire header to make room.

### `pe/packer/stubgen/stage1/stub.go` (REPLACES round.go)

```go
// EmitStub writes a complete polymorphic decoder stub into the
// builder. The stub:
//   - Starts with CALL+POP+ADD prologue computing the .text section's
//     runtime address into the chosen base register (typically R15
//     to keep RAX/RCX/RDX scratch).
//   - Runs N decoder loops (rounds[N-1] first, peeling outermost
//     SGN layer) over the .text bytes IN PLACE.
//   - Finishes with ADD-displacement to convert .text base into OEP
//     address, then JMP via register.
//
// The stub is position-independent: all internal references go
// through the prologue-computed base register. No symbols, no
// post-emit patches.
//
// stubMaxSize gives the EmitStub function an upper bound; if the
// generated bytes would exceed it, returns ErrStubTooLarge so the
// caller can lower N or trim junk.
func EmitStub(b *amd64.Builder, plan transform.Plan, rounds []poly.Round) error
```

The `Plan` struct gives stage1 the RVA constants it needs for the
ADD-displacement immediates. All RVAs in `Plan` are pack-time
known — no late binding.

### `pe/packer/stubgen/stubgen.go`

```go
// Options for the new flow.
type Options struct {
    Input     []byte         // PE/ELF to pack
    Pipeline  []PipelineStep // existing Phase 1c+ pipeline for .text encryption
    Rounds    int            // SGN rounds (1..10)
    Seed      int64          // poly seed (0 = crypto/rand)
    StubMaxSize uint32       // default 4096
}

// Generate drives the full UPX-style flow. Replaces the previous
// host.EmitPE / EmitELF routing; this function now BOTH drives the
// transform AND emits the stub.
func Generate(opts Options) ([]byte /* modified binary */, []byte /* key */, error)
```

Pipeline:

```go
// 1. Detect format from magic.
// 2. plan, err := transform.PlanPE_or_ELF(opts.Input, opts.StubMaxSize)
// 3. textBytes := opts.Input[plan.TextFileOff : plan.TextFileOff + plan.TextSize]
// 4. encrypted, keys, err := PackPipeline(textBytes, opts.Pipeline)
//    key := keys[0] (single-step default)
// 5. eng := poly.NewEngine(opts.Seed, opts.Rounds)
//    finalEncoded, rounds := eng.EncodePayload(encrypted)
// 6. b := amd64.New()
//    stage1.EmitStub(b, plan, rounds)
//    stubBytes, _ := b.Encode()
//    if len(stubBytes) > plan.StubMaxSize { return ErrStubTooLarge }
// 7. modifiedBinary, err := transform.InjectStub_PE_or_ELF(opts.Input, finalEncoded, stubBytes, plan)
// 8. Self-test: re-parse modifiedBinary, verify it can be loaded as a target binary shape.
// 9. return modifiedBinary, key, nil
```

### `pe/packer/packer.go`

```go
func PackBinary(input []byte, opts PackBinaryOptions) ([]byte, []byte, error) {
    // Format detection by magic byte; route to stubgen.Generate
    // with appropriate Options.
}
```

`opts.Format` becomes optional/redundant — magic-byte detection
works for both PE and ELF — but kept for backwards API compat
with v0.59/0.60 callers (rejects mismatched explicit format vs
detected magic).

## Data flow

(See "Runtime flow" section above for the at-target picture; pack-time
flow is in stubgen.Generate above.)

## Error handling

All sentinels listed in the Plan struct above. Pre-return self-test
catches header-corruption bugs by re-parsing the output via
`debug/pe.NewFile` / `debug/elf.NewFile`.

## Testing strategy

### Unit tests

1. **`transform.TestPlanPE_ReturnsCorrectRVAs`** — synthetic minimal PE,
   verify Plan fields are computed correctly (StubRVA past last section,
   page-aligned, OEPRVA matches input).

2. **`transform.TestInjectStubPE_DebugPEParses`** — synthetic PE +
   dummy stub bytes, run InjectStubPE, parse output via `debug/pe.NewFile`,
   assert NumberOfSections incremented + entry point updated.

3. **`transform.TestInjectStubPE_RejectsTLSCallbacks`** — synthetic
   PE with TLS Directory, verify `ErrTLSCallbacks`.

4. **`transform.TestInjectStubPE_RejectsOEPOutsideText`** — synthetic
   PE with entry pointing into `.data`, verify `ErrOEPOutsideText`.

5. **Same set for `transform.elf.go`** — `TestPlanELF_*`,
   `TestInjectStubELF_DebugELFParses`, etc.

6. **`stage1.TestEmitStub_AssemblesCleanly`** — feed dummy plan +
   3 rounds, encode, verify stub bytes start with CALL opcode (0xE8).

7. **`stage1.TestEmitStub_RespectsMaxSize`** — verify `ErrStubTooLarge`
   when emitted bytes exceed `Plan.StubMaxSize`.

8. **`stubgen.TestGenerate_PerPackUniqueness`** — same input + seed=1
   vs seed=2 → Hamming distance ≥ 30% across the modified binary.

### E2E test (gated `maldev_packer_run_e2e`)

9. **`packer.TestPackBinary_LinuxELF_E2E`** (already shipped, currently
   failing) — pack `pe/packer/runtime/testdata/hello_static_pie_c`
   (the asm fixture from Phase 1f Stage E — minimal `.text` only,
   ideal candidate). Modified ELF runs, prints "hello from raw asm".
   **This test passing is the contract for shipping v0.61.0.**

10. **`packer.TestPackBinary_LinuxELF_E2E_GoStaticPIE`** (NEW, allowed
    to fail on v0.61.0) — pack `hello_static_pie` (Go static-PIE).
    Multi-section Go binaries may need extensions to encrypt more
    than `.text` for runtime to work correctly; flag as known
    limitation in v0.61.0 if it fails. The asm fixture is the gate.

11. **`packer.TestPackBinary_WindowsExe_E2E`** (deferred — needs
    Windows VM; same as 1e-A's deferred test).

### Cross-platform sanity

- All `transform/*` code is cross-platform: parses PE/ELF byte buffers
  via low-level encoding/binary, no syscalls.
- `GOOS=windows` and `GOOS=darwin` builds clean.

## Migration

This rewrite REPLACES Phase 1e-A (v0.59.0) and Phase 1e-B (v0.60.0).
The shipped tags stay (no rollback) but the documented behavior
changes: those tags ship "byte-shape correct, runtime broken" code,
and v0.61.0 ships the working architecture.

The `pe/packer/runtime` package stays untouched. Its API (`LoadPE`,
`Prepare`, etc.) remains available for operator code that wants
manual reflective loading. Phase 1f Stages A-E (the runtime gate +
mapper) continue to work as documented.

`cmd/packer pack -format=windows-exe / linux-elf` keeps the same
operator-facing flags. Underlying flow goes from "broken host
emit" to "UPX-style transform" — invisible to the CLI user.

The currently-failing E2E test
(`pe/packer/packer_e2e_linux_test.go`) flips from regression guard
to passing test in v0.61.0.

## Future work

- **v2: extend encryption to `.data`/`.rdata`** — needs a careful
  audit of which sections the kernel reads at load time
  (Import Directory, Resource Directory, Reloc Directory all stay
  plaintext; per-section opt-in via `opts.EncryptSections []string`).
- **v3: stub flips RWX → R+E after decrypt** via `mprotect` /
  `VirtualProtect`. Requires symbol resolution (PEB walk on Windows;
  vDSO syscall on Linux). Reduces the RWX-section AV signal.
- **v4: import-table encryption** — encrypt the IAT byte slot
  references and resolve dynamically in the stub. Eliminates one
  of the most-fingerprinted PE static surface artifacts.
- **Stage 1e-C/D/E** (DLL host / BOF / .NET) — different output
  shapes. DLL fits the UPX model directly (modify the input DLL).
  BOF and .NET are different format families, separate specs.

## See also

- `docs/refactor-2026-doc/KNOWN-ISSUES-1e.md` — record of the gap this
  spec closes.
- `pe/packer/runtime/` — reflective loader unchanged.
- `pe/morph/`, `pe/strip/`, `pe/dllproxy/` — existing repo PE-modify
  primitives we'll lean on.
- UPX source — `src/p_w64pep.cpp` (PE), `src/p_lx_elf.cpp` (ELF) —
  reference architecture.
