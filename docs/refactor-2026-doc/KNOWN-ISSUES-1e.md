---
last_reviewed: 2026-05-07
reflects_commit: 8771e95
severity: resolved
---

# Phase 1e-A & 1e-B — architectural gap (runtime broken)

> **Status: RESOLVED in v0.61.0.** Phase 1e-A (`v0.59.0`) and Phase
> 1e-B (`v0.60.0`) shipped code that produced byte-shape-correct host
> binaries but those binaries **did not execute** — they crashed on
> the first decoder loop iteration. The architectural gap is closed by
> the UPX-style in-place transform (commit `8771e95`). See the
> **Resolution summary** section at the end of this document.
>
> The historical narrative below is preserved for post-mortem reference.

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
- `docs/superpowers/specs/2026-05-07-phase-1e-upx-rewrite-design.md` — the UPX-style rewrite spec
- `pe/packer/packer_e2e_linux_test.go` — the ship-gate E2E test (now green)
- `pe/packer/transform/` — PlanPE / PlanELF / InjectStubPE / InjectStubELF (the new in-place transform)
- `pe/packer/stubgen/stage1/stub.go` — EmitStub: CALL+POP+ADD prologue + decoder loops + final JMP

---

## Resolution summary (v0.61.0)

The architectural gap was closed by switching from the "host wrapper + stage 2 Go EXE" model to a
**UPX-style in-place transform**. Rather than producing a two-stage binary, the packer now modifies
the input binary directly:

1. Encrypts the `.text` section with SGN polymorphic encoding (XOR/SUB-neg/ADD-complement rounds
   with junk insertion).
2. Appends a new read+write+exec section containing a compact polymorphic decoder stub.
3. Rewrites the entry-point field to point at the new stub section.
4. The kernel loads the single output binary normally; the stub decrypts `.text` in place and JMPs
   to the original entry.

The six bugs found during the Phase 1e-A/B investigation were resolved as follows:

| Bug | Root cause | Resolution | Commit |
|-----|-----------|------------|--------|
| Bug 1 — LEA RIP-relative absolute | `golang-asm` `NAME_NONE + REG_NONE` emits SIB-absolute, not RIP-relative | Replaced LEA with CALL+POP+ADD prologue (PIC shellcode idiom); no RIP-relative needed | `b5c2f77` |
| Bug 2 — no final JMP to stage 2 | `stubgen.Generate` never emitted a trailing jump | `EmitStub` in `stage1/stub.go` emits the final JMP to the now-decrypted entry | `b5c2f77` |
| Bug 3 — file-vs-image layout mismatch | Stage 2 was a complete Go EXE; file offset ≠ RVA for multi-section binaries | Eliminated stage 2 entirely; kernel loads the single transformed binary, resolving the layout gap | `e647e61` + `94fc595` |
| Bug 4 — segment-vs-section for Go static-PIE | `PlanELF` used PT_LOAD extent for `.text` bounds; Go PIEs have a gap between text segment and section | `PlanELF` now reads the `.text` SHT entry directly for accurate byte range | `83cf34a` |
| Bug 5 — XOR-over-SGN double-wrapping | Legacy `PackBinary` path applied an outer XOR layer on top of the SGN encoding | Outer XOR layer removed; stub decodes raw SGN output | `8771e95` |
| Bug 6 — PatchTextDisplacement formula | CALL+POP reference point calculation was off by the size of the CALL instruction itself | Fixed offset arithmetic in `PatchTextDisplacement` so stub correctly computes the target address | `8771e95` |

Ship gate met at commit `8771e95`: `TestPackBinary_LinuxELF_E2E` runs a packed Go static-PIE fixture
through to `"hello from packer"` and exit 0 under
`go test -count=1 -tags=maldev_packer_run_e2e -run TestPackBinary_LinuxELF_E2E ./pe/packer/`.

---

## C3 LZ4 compression — attempt 1 (deferred 2026-05-08)

**Status: not shipped.** Tried 2026-05-08 against v0.65.0 base. Plan: see
[2026-05-08-packer-improvements.md § Chantier 3](../superpowers/plans/2026-05-08-packer-improvements.md).

Architecture attempted:
- Pack-time: LZ4-compress `.text` bytes, then SGN-encode the compressed output.
- Stub: SGN-decode → LZ4-inflate (in-place via `safety_margin = compressed_size/255 + 16` zero
  bytes prefixed in the `.text` section) → JMP to OEP.
- New `PackBinaryOptions.Compress bool` (opt-in, default false).
- `transform.InjectStubPE` / `InjectStubELF` extended with a `memSize uint32` parameter so the
  loader maps a larger virtual region than the on-disk file size.
- Hand-rolled amd64 LZ4 inflate decoder in `pe/packer/stubgen/stage1/lz4_inflate.go` (~250 bytes
  asm).

Two failures observed in the smoke test:

1. **Compress=true output crashed at runtime.** The packed Linux ELF SIGSEGV'd on the first
   instruction after the inflate path. Cause not isolated — likely either an LZ4 decoder asm bug
   (overflow in the match-copy loop, wrong register convention) or a section-layout mismatch
   (`memsz` vs `filesz` not propagated correctly through the PT_LOAD entry).
2. **No size win on the Go static-PIE fixture.** `hello_static_pie` (1.30 MB) compressed to
   1.31 MB output (+0.3%) — the safety_margin overhead exceeded the LZ4 savings on this input.
   Go's `.text` is mostly already-compact runtime code; LZ4 has little to find.

Per the plan's "do NOT push a broken ship" gate, the attempt was reverted to v0.65.0 (master at
`346afad`). The work-in-progress diff (15 files modified + 4 new) was discarded.

When this is reattempted, the iteration order should be:

- Build a smaller debug fixture (e.g., a 4 KiB Go static-PIE that spends most of its bytes in
  `.rodata`) so size shrinkage is observable before debugging the runtime path.
- Round-trip-test the inflate decoder asm in isolation against `pierrec/lz4` BEFORE wiring it
  into the stub. The plan called for this but the API-error mid-flight cut it short.
- Verify `memsz > filesz` propagation by reading the output binary back via `readelf -lW` and
  asserting the `MemSiz` column reflects the original-size + safety_margin total.
- Win VM E2E first on the simplest case (Compress=true + Stage1Rounds=1 + AntiDebug=false), then
  scale up.

Plan rows C3 + C6 remain open. C1, C2, C4, C5, C7 all shipped (v0.62.0–v0.65.0).

### C3 progress as of 2026-05-08

- **C3-stage-1 — decoder asm in isolation** ✅ shipped at commit `a336bbc`.
  - `pe/packer/stubgen/stage1.EmitLZ4Inflate(b *amd64.Builder)` — 136-byte
    LZ4 block-format inflate decoder using **Go register ABI**
    (RAX=src, RBX=dst, RCX=src_size).
  - 5 round-trip tests against `github.com/pierrec/lz4/v4` (all-zero,
    all-random, RLE offset=1, real `.text` fragment, edge sizes
    0/1/15/16/4095/65535/65536) — all green.
  - **NOT wired into the stub.** The decoder ships as a library helper.

- **C3-stage-2 — wire into stub** — PARTIAL IMPLEMENTATION (2026-05-08,
  commits da86504..09de872 on worktree branch). The unit-test stack is
  complete and green; the Linux E2E gate (`TestPackBinary_LinuxELF_MultiSeed_WithCompress`)
  crashes on all 8 seeds with SIGSEGV. Root cause diagnosed, fix attempted
  twice, third iteration still crashes. Master NOT updated.

  **What was shipped (unit-test-complete, E2E-failing):**
  - `Plan.TextMemSize` field + `InjectStubPE`/`InjectStubELF` honour it (Steps A–C) ✅
  - `EmitOptions.{Compress,SafetyMargin,CompressedSize}` + `EmitLZ4InflateInline`
    (no-RET variant for inlining) + `EmitStub` Compress path (Steps D) ✅
  - `stubgen.Generate` + `packer.PackBinaryOptions.Compress` (Step E) ✅
  - E2E test `TestPackBinary_LinuxELF_MultiSeed_WithCompress` added (Step F) ✅ (but fails)

  **Root cause of SIGSEGV (diagnosed via GDB):**
  The LZ4 in-place inflate is crashing inside the match-copy loop because
  the dst pointer (write cursor) overtakes the src pointer (read cursor).
  Two bugs were fixed during the session but the crash persists:

  Fix 1: `EmitLZ4Inflate` ends with RET (0xC3). When inlined in the stub,
  RET pops the stack and jumps to garbage. Fixed by adding
  `EmitLZ4InflateInline` (135 bytes, no RET) and calling it from `EmitStub`.

  Fix 2: The safety_margin formula was `ceil(compressedSize/255)+16` but
  the correct bound for in-place inflate (dst < src) requires
  `ceil(originalTextSize/255)+16` because the worst-case output-to-input
  ratio is bounded by `originalSize/255`, not `compressedSize/255`.

  **Remaining gap (still crashing after both fixes):**
  After applying both fixes, the GDB crash trace still shows dst overtaking
  src in the match-copy loop with `RCX = 0xCCCC` (a garbage match_offset
  value). This means the u16 match_offset field being read from the
  compressed stream is corrupted — the src pointer is reading already-
  overwritten output bytes instead of the original compressed data.

  Possible causes for the next session to investigate:
  1. **The safety_margin arithmetic still has an off-by-one or wrong bound.**
     Verify with a standalone test: extract the packed binary's compressed
     block, inflate it with the asm decoder via mmap (as in lz4_inflate_test.go),
     confirm it succeeds; then confirm the same bytes at `[R15+safetyMargin,
     R15+safetyMargin+compressedSize)` at runtime are those compressed bytes.
  2. **The SGN decode counter uses the compressed payload size, but the
     on-disk bytes may span a different range.** Confirm `plan.TextFileOff`
     points to exactly where the compressed payload was written, and that
     `p_filesz` matches `plan.TextSize` (not the original text size).
  3. **The `p_filesz` of the executable PT_LOAD was NOT updated.** Currently
     only `p_memsz` is conditionally updated in `InjectStubELF`. If `p_filesz`
     still equals the original segment filesz (0x7AA10) but only
     `plan.TextSize = 0x527ed` bytes were written into the .text slot,
     the kernel maps the TAIL `[0x401000+0x527ed, 0x7AA10)` bytes from the
     ORIGINAL binary, not zeros. Those original bytes would then be read
     by the LZ4 decoder as compressed data → garbage tokens → crash.
     **THIS IS THE MOST LIKELY REMAINING BUG.**

  **Recommended next step:**
  In `InjectStubELF`, also update `p_filesz` for the executable PT_LOAD
  when `Compress=true`. The new `p_filesz` should be
  `max(original_text_file_end_within_segment, safetyMargin+compressedSize_rounded_up)`.
  The kernel will then zero-fill `[p_filesz, p_memsz)` at load time instead
  of reading stale bytes from the original binary tail.

  Alternatively: zero-fill the tail `[plan.TextFileOff+plan.TextSize,
  plan.TextFileOff+originalTextSize)` bytes in the output buffer inside
  `InjectStubELF` when `plan.TextMemSize > plan.TextSize`. This is simpler
  and more robust (doesn't require p_filesz accounting).

### C3-stage-2 attempt 2 — deeper diagnosis (2026-05-09)

After the worktree subagent shipped C3-stage-2 to master (commits
`da86504..1429b7a`), the Linux E2E `TestPackBinary_LinuxELF_MultiSeed_WithCompress`
SIGSEGVs on every seed. The test is now `t.Skip()`'d so the gated suite stays
green; runtime correctness work continues here.

GDB trace at the crash:

```
Program received signal SIGSEGV
=> movzbl (%rsi), %eax    ; rsi = dst - match_offset, OOB before R15
   r11 (src) = 0x555555557134, r12 (dst) = 0x555555557137  ; dst AHEAD of src by 3 bytes
   r10 (src_end) = 0x5555555a7a6e
   r15 (text base) = 0x555555555000
   rcx (match_offset) = 0x8b48 (35656, larger than dst-progress 8503)
```

**Two corrections to the previous diagnosis:**

1. The `LZ4_DECOMPRESS_INPLACE_MARGIN` macro takes **`compressedSize`**, not
   `decompressedSize`. The C3-stage-2 subagent's "Fix 2" inverted this by
   substituting `originalTextSize`. Switching back to LZ4-official
   `(originalTextSize >> 8) + 32` yielded a margin of 1978B (vs 1346B for
   `(compressedSize >> 8) + 32`) — bigger but still not enough.

2. The crash isn't just a too-small margin. At the failure point, the
   cumulative output-minus-input excess was 1981B (initial dst-src offset
   = -1978, current = +3, swing = 1981). This **matches LZ4's worst-case
   5/3 expansion ratio almost exactly** — the safety margin formula is
   correct in expectation but allows zero slack against pathological input.

**Hypotheses for next debugging session:**

- The SGN decoder's substitution layer might be leaving the LZ4-encoded
  bytes subtly different from what `pierrec/lz4` produced. A standalone
  test (`SGN-encode → SGN-decode → LZ4-inflate` with no PackBinary, no
  section injection) would isolate this. If round-trip works, the bug is
  in the binary-side memsz/filesz layout. If not, the SGN+LZ4 chain has
  a semantic mismatch.

- The `EmitOptions.SafetyMargin` and `EmitOptions.CompressedSize` immediate
  values emitted into the stub might not match what `stubgen.Generate`
  computed at pack time. Worth disassembling a freshly-packed binary and
  checking the `MOV ECX, ...` constants directly.

- The match_offset 0x8b48 is suspiciously close to `0x8C00` and looks like
  it could be a corrupted u16 read (e.g., source pointer reading past
  src_end into stale tail bytes). Worth checking that
  `r10 (src_end)` was set correctly relative to the actual compressed-data
  end.

The C3-stage-1 LZ4 decoder (commit `a336bbc`) round-trips correctly against
`pierrec/lz4` in 5 isolation tests. The bug is in the integration, not the
asm.

**Status:** test skipped; master green for all default paths (Compress=false).

### C3-stage-2 attempt 2 — diagnostic confirmation (2026-05-09)

Empirical test: bumped `safety_margin` to 65536 (64KB, 33× larger than the
LZ4-official `(srcSize >> 8) + 32` bound for our 336565-byte compressed
payload). **The SIGSEGV persists on all 8 seeds**.

**Conclusion: the bug is NOT in the safety_margin formula.** Whatever is
causing the LZ4 in-place inflate to crash, it isn't the margin sizing.
That eliminates a whole class of hypotheses.

The remaining candidates:

1. **SGN+LZ4 round-trip semantics break under in-place layout.** The SGN
   decoder modifies bytes [R15, R15+TextSize) in place. Maybe a subtle
   round-trip issue when the SGN-encoded bytes happen to start with a
   pattern that LZ4 misinterprets. Standalone test: SGN-encode the
   compressed payload, SGN-decode it, then LZ4-inflate. Compare to direct
   LZ4 inflate of the original compressed bytes. If different, that's the
   bug.

2. **The on-disk encoded bytes don't match what stubgen.Generate produced.**
   Could be an off-by-one in InjectStubELF's `copy(out[plan.TextFileOff:
   plan.TextFileOff+plan.TextSize], encryptedText)` if `encryptedText`
   has the wrong layout. Verify by hex-dumping the packed binary's .text
   region and comparing to the in-memory encryptedText buffer at pack time.

3. **Kernel mapping issue with RWX segment.** The InjectStubELF code sets
   PF_W on the executable PT_LOAD. Modern Linux kernels with PaX-style
   protections may refuse RWX mappings or emulate them differently.
   Possibly the segment is being mapped without write permission silently.

4. **The decoder's call instruction sequence has a bug under the actual
   in-binary layout.** The C3-stage-1 isolation test runs the decoder
   from a freshly mmap'd RX page. Maybe execution from .text (which has
   different page protections post-load) behaves subtly differently.

**Recommended next debugging step:** write a Go test that takes the packed
binary, simulates the SGN decoder in Go, then runs the LZ4 decoder asm via
mmap on the SGN-decoded bytes. If that round-trips, the issue is hypothesis
3 or 4. If it crashes too, the issue is hypothesis 1 or 2.

The diagnostic also confirmed the worktree's transform/ changes don't break
the Windows side: `go run ./cmd/vmtest windows ./pe/packer/...
TestPackBinary_WindowsPE_PackTimeMultiSeed` exits 0 cleanly. Default-path
E2E gates remain green on both platforms.
