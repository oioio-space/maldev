---
last_reviewed: 2026-05-07
reflects_commit: b0e08ff
severity: critical
---

# Phase 1e-A & 1e-B — architectural gap (runtime broken)

> **Status: critical.** Phase 1e-A (`v0.59.0`) and Phase 1e-B
> (`v0.60.0`) ship code that produces byte-shape-correct host
> binaries (`debug/pe`, `debug/elf` parse them cleanly) but those
> binaries **do not execute** — they crash on the first decoder
> loop iteration. Both tags are misleadingly aggressive; the
> shipped feature is not yet operational.
>
> This doc records the findings, the regression guard, and the
> proposed fix path so the next session can prioritise it.

## How the gap was discovered

`pe/packer/packer_e2e_linux_test.go` — a build-tagged E2E test
shipped 2026-05-07 — packs the Phase 1f Stage E
`hello_static_pie` fixture via `packer.PackBinary(FormatLinuxELF)`,
writes the resulting ELF to a temp file, execs it with
`MALDEV_PACKER_RUN_E2E=1`. The subprocess exits with signal-killed
status (`exit -1`) and zero stdout/stderr. The payload's expected
"hello from packer" never appears.

Disassembling the generated stage 1 confirms the cause:

```
0x1000: 49 c7 c3 a6 e2 82 00    mov    $0x82e2a6, %r11        ; cnt = payload len
0x1007: 48 c7 c7 2b 00 00 00    mov    $0x2b, %rdi            ; key
0x100e: 4c 8d 04 25 00 00 00 00 lea    0x0, %r8               ; src = ABSOLUTE 0 (BUG)
0x1016: 49 0f b6 00             movzbq (%r8), %rax            ; READ FROM NULL → SIGSEGV
```

`%r8` is loaded with absolute zero, not the encoded payload's
runtime address. First `MOVZBQ (%r8), %rax` of the decoder loop
dereferences NULL → SIGSEGV.

## Root cause

### Bug 1: `amd64.Builder.LEA` does not emit RIP-relative addressing

`pe/packer/stubgen/amd64/builder.go::setOperand` for
`MemOp{RIPRelative: true, Label: "..."}` sets:

```go
addr.Type = obj.TYPE_MEM
addr.Name = obj.NAME_NONE
addr.Reg = x86.REG_NONE
addr.Offset = int64(v.Disp)
```

`golang-asm` interprets `NAME_NONE + REG_NONE + Offset` as
**absolute** SIB-encoded addressing (`[disp32]`), not
RIP-relative (`[rip+disp32]`). To get a true RIP-relative LEA
without a real symbol table (we have none — we use golang-asm
purely as a byte emitter), the path is non-obvious. golang-asm's
RIP-relative addressing in production assumes the linker
resolves `NAME_EXTERN` references — but the maldev packer has no
linker stage.

The generated LEA is structurally valid but semantically wrong:
it loads a NULL pointer instead of the encoded blob's address.

### Bug 2: no final JMP to stage 2's entry

Even with Bug 1 fixed, `stage1.Round.Emit` ends each round at
`JNZ loop_X` and never emits a final JMP from end-of-stage-1
into the decoded stage 2's entry point. After the last round's
loop completes, RIP falls through into whatever bytes follow —
either alignment padding or section-boundary garbage → SIGSEGV.

`stubgen.Generate` orchestrates the rounds but doesn't append a
trailing JMP either.

### Bug 3 (consequential): stage 2 isn't JMP-friendly

Stage 2 today (`stubvariants/stage2_v01.exe` and
`stage2_linux_v01`) is a complete Go EXE / static-PIE. Even if
Bugs 1 + 2 were fixed and stage 1 could compute the encoded
blob's address + JMP somewhere within it, the JMP target needs
to land at the Go runtime's `_rt0_amd64_*` entry point.

The runtime entry's offset within the binary file does NOT match
its offset within the in-memory image (file_offset ≠ rva for
multi-section PEs / ELFs). For a Go EXE with multiple sections
(text, rodata, data, ...), the in-memory layout has gaps the
file doesn't have — JMPing to "blob_addr + e_entry RVA" lands
at the wrong bytes.

The "encoded blob is a complete PE/ELF" assumption breaks the
JMP-into-it model.

## Why the unit tests pass

All `pe/packer/stubgen/*` unit tests assert **byte-shape
correctness**:

- `host.EmitPE_ParsesViaDebugPE` — debug/pe accepts the bytes
- `host.EmitELF_ParsesViaDebugELF` — debug/elf accepts the bytes
- `stubgen.Generate_ProducesParsablePE/ELF` — same
- `poly.EngineEncodeDecodeRoundTrip` — Go-side decode round-trips
  cleanly (the asm half is never executed)
- `stage1.Emit_AssemblesCleanlyForAllSubsts` — the asm assembles
  to non-zero bytes (but never runs)

None of these tests **execute** the generated binary. The
self-test in `stubgen.Generate::selfTestRoundTrip` runs the
**Go-side mirror** of the SGN decoder, which doesn't share code
with the asm path. So the asm could be totally broken and the
self-test still pass.

The Phase 1e-A E2E test was deferred ("requires Windows VM
scheduling"). Phase 1e-B's E2E test SHIPS NOW — and catches
the gap.

## Proposed fix path

### Option A — CALL+POP+ADD (PIC shellcode idiom)

Replace LEA-RIP-relative entirely with classical shellcode address
discovery:

```
prologue:
    CALL .here
.here:
    POP r15                  ; r15 = address of .here
    ADD r15, displacement     ; displacement = end_of_stage1 - here_offset
                              ; r15 now = encoded blob's runtime address
    ; pass r15 through all rounds via the "src register" slot
```

Each round's setup uses `MOV src, r15` (no LEA needed). The
displacement is computed at pack time = `len(stage1_asm) -
(offset_of_pop_+1)`.

Tractable, but the displacement depends on cumulative round
sizes (which depend on junk insertion choices made per pack).
Two-pass assembly OR post-Encode patching is needed to compute
the correct displacement.

### Option B — Replace LEA with raw-byte emission + post-patch

`amd64.Builder` gains `EmitRawLEARelative(reg, sentinel)` that
emits the 7-byte `LEA reg, [rip+disp32]` encoding directly with
a sentinel disp32 (e.g., 0xCAFEBABE). After `Encode()`, scan
output for the sentinel and patch.

Smaller diff than Option A, but introduces a magic sentinel that
must be unique within the assembled bytes.

### Option C — Stage 2 as PIC shellcode (Donut)

The deeper architectural rework: instead of stage 2 being a Go
EXE that's JMP'd into, stage 2 is **position-independent
shellcode** (a Donut-converted version of `stage2_main.go`)
that's JMP-safe at any offset. `pe/srdi`'s existing Donut
integration provides this.

Stage 1 then simply computes encoded blob's runtime address +
JMPs to offset 0 of decoded blob. Donut's loader handles the
rest (parses the embedded PE, reflectively loads it, calls main).

**Strongest correctness guarantee.** Trade-off: bigger output
(~2 MB shellcode + Donut overhead) and changes the stage 2 model
from "Go EXE with sentinel-located trailer" to "Donut-shellcode
with embedded payload". README/Makefile updates needed.

### Final JMP

Independent of A/B/C, `stubgen.Generate` must emit a final JMP
after the last round's loop:

```go
b.JMP(srcReg)   // jump to (encoded_blob_address + 0) where
                // stage 2's runnable entry now lives after decoding
```

(Assuming Option C — for Options A/B with stage 2 = real Go EXE,
the JMP target needs entry-offset adjustment which is itself
fraught — see Bug 3.)

## Recommendation

**Option C** + the final JMP. Switching stage 2 to Donut shellcode
is the cleanest fix; Options A/B don't address Bug 3 (Go EXE's
file-vs-image layout incompatibility).

Effort estimate: ~600 LOC. Refactors:

- `pe/packer/stubgen/stubvariants/Makefile` — add a Donut
  conversion step after the Go build
- `pe/packer/stubgen/stubvariants/stage2_v01.exe.donut` and
  `stage2_linux_v01.donut` — committed Donut shellcode
  (smaller than the Go EXE in some cases, larger in others —
  measure)
- `pe/packer/stubgen/stubgen.go` — embed the Donut blob; drop
  the patch-stage2-with-sentinel logic; build the inner blob
  as `donut_shellcode || trailer`
- `pe/packer/stubgen/stage1/round.go` — emit final JMP via
  CALL+POP+ADD-loaded register
- `pe/packer/stubgen/host/{pe.go, elf.go}` — single section
  R+W+X (or two sections with the second one R+W+X) so the
  decoded blob is both readable, writable, and executable.
- E2E test — already shipped as the regression guard.

## Tags v0.59.0 / v0.60.0

These tags claim Phase 1e-A and 1e-B are shipped. **They are
shipped at the byte-shape level but not at the execution level.**
Honest framing: the unit-test surface works; the E2E surface
exposes the gap.

Two paths forward:

1. **Keep the tags, add a Known-Issues banner to the docs**
   (this file + handoff). The user can flip operational use
   on once the architectural fix ships.

2. **Move the tags backward** (delete the v0.59.0/v0.60.0 tags
   on origin, retag once the fix lands). Operationally
   awkward but more honest.

Recommendation: **Option 1.** The code IS correctly shipped at
the byte-shape level — the unit tests prove that. The E2E gap
is documented here and will close with the next ship. Delete
the docs claiming "operationally complete"; the runtime path
needs follow-up work.

## See also

- `docs/superpowers/specs/2026-05-07-phase-1e-a-polymorphic-packer-stub-design.md`
- `docs/superpowers/specs/2026-05-07-phase-1e-b-linux-elf-host-design.md`
- `pe/packer/packer_e2e_linux_test.go` — the regression guard
- `pe/packer/stubgen/stage1/round.go` — where the final JMP must be added
- `pe/packer/stubgen/amd64/builder.go::setOperand` — where LEA RIP-relative emission is broken
- `pe/srdi/` — Donut integration that Option C would reuse
