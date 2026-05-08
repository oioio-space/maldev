# Packer Improvements Plan — post-v0.61.1

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take the v0.61.1 UPX-style packer from "operationally correct, well-tested" to "operationally hard to detect" by closing the static-analysis cover gap, raising the runtime polymorphism, and shipping per-build variance levers operators can flip without re-architecting.

**Architecture:** Each chantier is independent and ships behind a feature flag in `PackBinaryOptions` so the v0.61.1 happy path stays the conservative default. Order is from "lowest risk + highest value" to "biggest design lever". Each chantier has its own E2E gate.

**Tech Stack:** Go 1.21 baseline (no cgo). Pure-Go PE/ELF byte manipulation. SGN polymorphic engine. AMD64 amd64 asm via `golang-asm`. Build/test on linux/windows/darwin; runtime on Windows + Linux.

---

## Inventory of remaining levers

The /simplify subagents flagged seven deferred items in the post-audit review. Plus the brainstormed candidate list (six items) the user already proposed. Cross-checking both:

| Source | Item | Disposition |
|---|---|---|
| Brainstorm A | PHT relocation v2 (ELF cover) | **Chantier 1** — concrete, well-scoped |
| Brainstorm B | Fake imports PE (cover layer v2) | **Chantier 2** — needs Windows VM |
| Brainstorm C | Compression activated by default | **Chantier 3** — pipeline integration |
| Brainstorm D | Anti-debug runtime in stub | **Chantier 4** — touches stub |
| Brainstorm E | Stub size reduction | **Chantier 5** — co-evolves with 4 |
| Brainstorm F | Multi-target bundle | **Chantier 6** — design + new format |
| Simplify Q4 | stubgen orphaned `key` return | **Chantier 7** — API cleanup |
| Simplify Q11 | Split `runtime_linux.go` (513 LOC) | Cosmetic — descope |
| Simplify Q12 | Split `entropy.go` | Cosmetic — descope |
| Simplify Q2 | `pipeline.go` ErrBadMagic misuse | **Chantier 7** — bundle with the API cleanup |
| Simplify R1 | Promote `random.Int64()` helper | **Chantier 7** — bundle |

Total: **6 feature chantiers + 1 API cleanup**.

## Ordering directive

Work the chantiers in the listed order — do NOT round-robin. Each ships independently; later chantiers can build on earlier ones. Tagged release at every chantier closure.

1. **C1 PHT relocation v2** — operator-visible win + frees Go-static-PIE from `ErrCoverSectionTableFull` today.
2. **C2 Fake imports PE** — symmetric Windows win; needs Win VM E2E.
3. **C3 Compression by default** — single-line knob, big size reduction; co-evolves with C2 cover.
4. **C4 Anti-debug runtime** — first stub-touching chantier; gates the polymorphism story.
5. **C5 Stub size reduction** — micro-architecture; depends on C4 baseline.
6. **C6 Multi-target bundle** — biggest design + format change.
7. **C7 API cleanup** — orphaned key, ErrBadMagic, Int64 helper. Bundle at any quiet point.

---

## Chantier 1 — PHT relocation v2 (ELF cover lift)

**Files:**
- Modify: `pe/packer/cover_elf.go` (new code path when no PHT slack)
- Test: `pe/packer/cover_elf_test.go` (new happy path against real Go static-PIE fixture)
- Test (E2E): `pe/packer/packer_e2e_seeds_linux_test.go` (extend multi-seed to also exercise cover layer)
- Doc: `docs/techniques/pe/packer.md` Limitations rewrite (PHT-slack constraint goes from "blocker" to "fall-back path")

**Goal:** When `AddCoverELF` detects no PHT slack between the existing PHT and the first PT_LOAD's file offset, relocate the PHT to file-end inside a new R-only PT_LOAD whose vaddr satisfies the kernel's `AT_PHDR = first_load_vaddr + e_phoff` invariant.

**Architecture:**

The kernel computes `AT_PHDR` as `first_PT_LOAD.vaddr + ehdr.e_phoff`. For Go static-PIE binaries `first_PT_LOAD.vaddr = 0x400000` and `ehdr.e_phoff = 0x40`, both fitting inside the segment. To relocate the PHT, we must keep this arithmetic valid:

- Pick a vaddr `V` above all existing PT_LOADs (high half of the address space, e.g., `last_load_vaddr_end + 0x10000`).
- Pick a file offset `F = V - first_PT_LOAD.vaddr` so that `AT_PHDR = first_load_vaddr + F = V` lands inside the new PT_LOAD's mapping.
- Add a new `PT_LOAD` entry covering `[F, F + new_pht_size)` → `[V, V + new_pht_size)` R-only.
- Update `e_phoff = F`.
- Update `PT_PHDR` entry (if present) to `(F, V, new_pht_size)`.
- Append the cover PT_LOADs in sorted-vaddr order at the end of the new PHT.
- Write the entire new PHT at file offset `F`; the old PHT bytes can be left in place (kernel reads from `e_phoff`, ignores the old location).

**Risk:** AT_PHDR mathematics is per-loader. Linux kernel binfmt_elf.c is the spec; ld.so + Go runtime must accept the AT_PHDR value. Requires the multi-seed E2E test to confirm runtime correctness.

**Steps:**

- [ ] **Step 1: Add the PHT-slack-fallback decision in AddCoverELF.**

  Locate the slack check at `cover_elf.go` ~ line 70. Before returning `ErrCoverSectionTableFull`, branch into a new helper `relocatePHT(input []byte, opts CoverOptions) ([]byte, error)`. Existing behavior preserved when slack is sufficient.

  ```go
  newTableEnd := phoff + uint64(uint16(phnum)+uint16(len(opts.JunkSections)))*uint64(phentsize)
  if newTableEnd > firstPTLoadFileOff {
      return relocateAndCoverELF(input, opts, /* parsed phdrs */)
  }
  ```

- [ ] **Step 2: Implement relocateAndCoverELF (new file: `cover_elf_reloc.go`).**

  Pseudo-code already in this plan's Architecture section. Plus 4 invariants to preserve:
  1. AT_PHDR = first_load_vaddr + new_e_phoff (math).
  2. PT_PHDR entry, if present, must be the FIRST phdr in the array (ELF spec — kernel rejects otherwise).
  3. PT_LOAD entries must be sorted ascending by p_vaddr (ELF spec — kernel rejects).
  4. The new file is page-aligned at `F` so the new PT_LOAD's mmap doesn't fail.

- [ ] **Step 3: Test it on a synthetic ELF that lacks slack.**

  Extend `minimalELF64WithSlack` to a sibling `minimalELF64NoSlack(textSize)` that places the first PT_LOAD at file offset 0 (mirroring Go static-PIE shape).

- [ ] **Step 4: Test it on the real Go static-PIE fixture.**

  `TestAddCoverELF_RelocatesPHTOnGoStaticPIE`: load `pe/packer/runtime/testdata/hello_static_pie`, call `AddCoverELF`, assert: (a) `debug/elf` parses, (b) PT_LOAD count = preLoadCount + 1 (new PT_LOAD covering relocated PHT) + len(JunkSections) cover PT_LOADs, (c) `e_phoff` changed.

- [ ] **Step 5: E2E runtime test on the relocated output.**

  Add to `packer_e2e_seeds_linux_test.go`: pack `hello_static_pie`, run `ApplyDefaultCover` (now expected to succeed via the relocation path), exec the resulting binary, assert exit code 0 + "hello from packer" stdout.

- [ ] **Step 6: Commit + push.**

  ```bash
  git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(pe/packer): PHT relocation lifts cover layer's Go static-PIE blocker

  When AddCoverELF detects no PHT slack between the existing
  program-header table and the first PT_LOAD's file offset, the
  cover layer now relocates the PHT to file-end inside a new R-only
  PT_LOAD whose vaddr satisfies the kernel's AT_PHDR invariant
  (first_load_vaddr + e_phoff = mapped vaddr). Go static-PIE
  binaries (which place first PT_LOAD at file offset 0) now go
  through the relocation path instead of returning
  ErrCoverSectionTableFull.

  4 ELF spec invariants preserved:
  1. AT_PHDR math (kernel binfmt_elf.c).
  2. PT_PHDR is the first phdr entry (ELF spec).
  3. PT_LOAD ordering by ascending p_vaddr (ELF spec).
  4. Page-aligned file + vaddr placement.

  Tests: synthetic-no-slack happy path, real Go static-PIE fixture
  via debug/elf round-trip, multi-seed E2E runtime confirming the
  packed binary still runs to clean exit.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
  ```

- [ ] **Step 7: Tag v0.62.0 (minor — additive feature).**

---

## Chantier 2 — Fake imports PE (cover layer v2)

**Files:**
- Create: `pe/packer/cover_imports.go` (new)
- Create: `pe/packer/cover_imports_test.go`
- Modify: `pe/packer/cover.go` (extend `CoverOptions` with `FakeImports []FakeImport`)
- Test (E2E): `pe/packer/packer_packtime_pe_test.go` extends the multi-seed to also exercise fake imports

**Goal:** Append fake `IMAGE_IMPORT_DESCRIPTOR` entries to a packed PE so static analyzers see additional benign-DLL imports. Kernel resolves them at load time (DLL must exist + function name must be a real export); the IAT addresses are populated but the binary's code never references them.

**Architecture:**

PE Import Directory at `DataDirectory[1]`:
- Array of `IMAGE_IMPORT_DESCRIPTOR` (20 bytes each), terminated by all-zero descriptor.
- Each descriptor:
  - `OriginalFirstThunk` → ILT (Import Lookup Table)
  - `Name` → null-terminated DLL name string
  - `FirstThunk` → IAT (Import Address Table)
- ILT/IAT entries (PE32+, 8 bytes):
  - High bit set: ordinal import (low 16 bits = ordinal)
  - High bit clear: RVA → `IMAGE_IMPORT_BY_NAME { Hint: u16, Name: zero-terminated }`

Approach: read existing descriptor table, build new table = `[existing_entries, fake_entries, zero_terminator]`, place new table + new ILT/IAT/Hint-Name strings + DLL name strings in a NEW R section. Patch `DataDirectory[1]` to point at the new descriptor table. Existing entries' `OriginalFirstThunk`/`FirstThunk` keep their original RVAs (kernel still populates the original IATs that the binary's code references).

Default fake list (real benign Windows API tuples — kernel won't reject):
```go
var DefaultFakeImports = []FakeImport{
    {DLL: "kernel32.dll", Functions: []string{"Sleep", "GetCurrentThreadId"}},
    {DLL: "user32.dll",   Functions: []string{"MessageBoxA", "GetCursorPos"}},
    {DLL: "shell32.dll",  Functions: []string{"ShellExecuteA"}},
    {DLL: "ole32.dll",    Functions: []string{"CoInitialize"}},
}
```

**Risk:** PE format is well-specified but the kernel rejects any unresolvable import. Test must confirm resolved imports load on Win10 + Win11 + Server 2019 LTSC (different default DLL versions).

**Steps:**

- [ ] **Step 1: Define `FakeImport` + `IMAGE_IMPORT_DESCRIPTOR` byte layout constants.**

  In a new `pe/packer/cover_imports.go`. Constants come from MSFT PE/COFF Spec Rev 12.0 § 6.4.

- [ ] **Step 2: Read existing import directory + build merged descriptor list.**

  ```go
  func mergeImportDirectory(input []byte, fakes []FakeImport) (newSection []byte, err error) {
      // 1. Parse DataDirectory[1] from optional header.
      // 2. Walk existing IMAGE_IMPORT_DESCRIPTOR array → existingDescriptors.
      // 3. Compute layout for fakes' ILT + IAT + Hint/Name + DLL strings.
      // 4. Emit new section bytes:
      //    [merged_descriptor_array, fake_ILTs, fake_IATs, fake_HintNames, fake_DLLnames]
  }
  ```

- [ ] **Step 3: Add `AddFakeImportsPE(input []byte, fakes []FakeImport) ([]byte, error)`.**

  Calls `mergeImportDirectory`, appends the new section via existing `AddCoverPE`-style section-table-grow logic, patches `DataDirectory[1]` RVA + size in the optional header.

- [ ] **Step 4: Tests on synthetic PE.**

  Synthetic input: `minimalPE32WithImports(numImports)` builds a PE with `numImports` existing entries. Verify `debug/pe` parses output, `len(parsed.imports) == numImports + len(fakes)`.

- [ ] **Step 5: Test on real Windows PE fixture.**

  Pack `pe/packer/testdata/winhello.exe` with PackBinary, then chain `AddFakeImportsPE` with `DefaultFakeImports`, verify `debug/pe` round-trips + import count grew.

- [ ] **Step 6: E2E runtime test on Windows VM.**

  Add to `packer_packtime_pe_test.go` (rename to `packer_e2e_windows_test.go` build-tagged): pack winhello.exe with `AddFakeImportsPE`, transfer to Windows VM via `cmd/vmtest`, exec, assert exit 0.

- [ ] **Step 7: Commit + push, tag v0.63.0.**

---

## Chantier 3 — Compression activated by default

**Files:**
- Modify: `pe/packer/stubgen.go` (Generate compresses .text before SGN-encoding)
- Modify: `pe/packer/stubgen/stage1/stub.go` (decoder undoes compression after SGN rounds)
- Test: extend multi-seed E2E to confirm size reduction + runtime correctness

**Goal:** Reduce packed-binary size by ~40-60% for typical Go binaries by chaining `compress.Flate` between the encrypt and SGN-encode steps. The stub gains an inflate pass after the last SGN round, before the JMP to OEP.

**Architecture:**

Current pipeline:
```
.text → SGN.Encode → .text' (same size) → place in output
                            ↓ runtime decode
                            .text (decoded back)
```

New pipeline:
```
.text → flate.Compress → .text_c (smaller) → SGN.Encode → .text_c' → place in output
                                                                  ↓ runtime: SGN.Decode → flate.Inflate → .text
```

The stub gains a tiny inflate decoder (Go's pure-Go inflate isn't usable in the stub — too big). Use raw DEFLATE via a hand-rolled inflate in amd64 asm, or ship a fixed-size compressor (LZ4 has a ~150-byte decoder).

**Decision required:** LZ4 vs custom-inflate vs aPLib. LZ4 is the smallest pure-decoder (≤200 bytes), ratio ~50%; aPLib is smaller decoder (~140 bytes) but GPL; custom-inflate balloons stub size.

**Recommendation:** LZ4 (BSD-3, smallest non-GPL) shipped via a hand-rolled decoder embedded as raw bytes (`amd64.RawBytes`).

**Risk:** Stub size budget (currently 4 KiB) may need bumping. Test required to confirm inflate output exactly matches pre-compression bytes (otherwise OEP JMP lands in garbage).

**Steps:**

- [ ] **Step 1: Add LZ4 compression path to `compress.go` (already partially scaffolded).**

  `CompressorLZ4` already exists as a placeholder. Wire it to a Go-side LZ4 encoder.

- [ ] **Step 2: Hand-craft the LZ4 decoder asm bytes (~200 bytes).**

  Reference: lz4.org/lz4_Block_format.md. Decoder fits in ~50 lines of amd64 asm.

- [ ] **Step 3: Bump `StubMaxSize` to 8 KiB (was 4) to absorb the LZ4 decoder + room for 5+ SGN rounds.**

- [ ] **Step 4: Wire compression into `stubgen.Generate`.**

  ```go
  encrypted := compress.Flate(textBytes)         // new
  encoded, rounds, _ := eng.EncodePayload(encrypted)
  // stub: SGN.Decode → LZ4.Inflate → JMP OEP
  ```

- [ ] **Step 5: Test size reduction.**

  Pack `winhello.exe` with + without compression, assert `(packed_with_compression_size / packed_without_size) < 0.7` (≥30% reduction).

- [ ] **Step 6: Multi-seed E2E + Windows VM E2E.**

- [ ] **Step 7: Commit + push, tag v0.64.0.**

---

## Chantier 4 — Anti-debug runtime in stub

**Files:**
- Modify: `pe/packer/stubgen/stage1/stub.go` (add anti-debug prologue)
- Modify: `pe/packer/PackBinaryOptions` (add `AntiDebug bool` flag, default `false`)
- Test: Windows VM E2E with debugger attached should fail-fast

**Goal:** Before the SGN decoder runs, the stub queries 3 anti-debug signals. Any positive returns to a benign instruction (`exit(0)`) instead of decrypting + jumping. Operator opt-in via `PackBinaryOptions.AntiDebug = true`.

**Architecture:**

Three checks (Windows-specific; ELF stubs skip):
1. **PEB.BeingDebugged** — single-byte read at `gs:[0x60].BeingDebugged`. ~10 bytes asm.
2. **PEB.NtGlobalFlag** — bit 0x70 set when debugger present. ~12 bytes.
3. **RDTSC delta** — measure cycles between two `RDTSC` reads bracketing a `CPUID`. >1000 cycles → debugger / VMexit. ~25 bytes.

Combined: `+50 bytes` in stub. Branches to `exit_clean` (RET to a fake stack) on positive.

ELF stubs skip — Linux ptrace detection is signal-handler-heavy and would balloon the stub. Operators bail via runtime checks in their payload instead.

**Risk:** False positives on real hardware (CET-enforced stacks, sleeping CPUs cause RDTSC blips). Threshold tuning against the matrix of (Win10, Win11) × (bare-metal, VM, sandboxed) is required. Operators in those environments should disable.

**Steps:**

- [ ] **Step 1: Add `AntiDebug bool` to `PackBinaryOptions`.**

- [ ] **Step 2: Emit anti-debug prologue when AntiDebug + Format=PE.**

  Insert AFTER the CALL+POP+ADD prologue, BEFORE the first SGN round. Branches negative continue; positive jumps to a `RET` (clean exit).

- [ ] **Step 3: Test the asm without anti-debug active (via debug/pe round-trip).**

- [ ] **Step 4: Smoke against `winhello.exe` on Windows VM:**

  - Pack with `AntiDebug=true`, exec normally → exit 0.
  - Pack with `AntiDebug=true`, exec under `windbg` → should fail-fast (exit code != 0 or no stdout).

- [ ] **Step 5: Commit + push, tag v0.65.0.**

---

## Chantier 5 — Stub size reduction

**Files:**
- Modify: `pe/packer/stubgen/stage1/stub.go` (instruction-density review)
- Modify: `pe/packer/stubgen/poly/junk.go` (configurable density)
- Modify: `pe/packer/stubgen/amd64/builder.go` (LEA via raw bytes for 7-byte savings)

**Goal:** Reduce baseline stub size from ~250 bytes (3 rounds, no anti-debug, no compression) to ≤180 bytes. Target: defeat the "UPX-like signature is constant" detection — by changing the FOOTPRINT, not just the per-pack bytes.

**Architecture:**

Three levers:
1. **Replace MOV imm64 with smaller equivalents.** `XOR reg, reg; OR reg, imm32` is 8 bytes vs `MOV imm64`'s 10 bytes for values fitting in 32 bits.
2. **Drop redundant instructions.** Some round emit MOV that's a no-op for the chosen substitution. Detection at emit time saves 3 bytes per round.
3. **Inline the loop counter into a register that doubles as src/dst pointer.** Saves 5+ bytes per round.

**Risk:** Aggressive size reduction may collapse stub variance and hurt polymorphism. Test that two consecutive packs still differ by ≥20 bytes.

**Steps:**

- [ ] **Step 1: Audit current stub byte sizes per round.**

- [ ] **Step 2: Implement size-reducing substitution-aware emitter.**

- [ ] **Step 3: Confirm polymorphism preservation.**

- [ ] **Step 4: Multi-seed E2E to confirm runtime correctness.**

- [ ] **Step 5: Commit + push, tag v0.66.0.**

---

## Chantier 6 — Multi-target bundle

**Files:**
- Create: `pe/packer/bundle.go` (new)
- Create: `pe/packer/bundle_test.go`
- Modify: `pe/packer/format.go` (new `BundleFormat` for the bundle blob format)
- Modify: `cmd/packer/main.go` (new `-bundle` flag)

**Goal:** Pack N payloads into one binary; at runtime the stub fingerprints the host (CPUID vendor + Windows build) and selects which payload to decrypt + JMP.

**Architecture:**

- Bundle format: `[stub_prologue, fingerprint_table, payload_1, payload_2, ..., payload_N]`.
- Each payload has a `target_match` predicate (e.g., `cpu_vendor == "GenuineIntel" && win_build >= 22000`).
- At runtime: stub queries CPUID + GetVersionExW, looks up matching predicate, decrypts only that payload, JMPs.

**Risk:** Big design — the bundle format is new and needs backward-compatibility considerations. Defer to a separate spec.

**Steps:**

- [ ] **Step 1: Brainstorm spec at `docs/superpowers/specs/2026-05-08-packer-multi-target-bundle.md`.**

- [ ] **Step 2: Implement post-spec.**

---

## Chantier 7 — API cleanup (bundle pickup)

**Files:**
- Modify: `pe/packer/stubgen/stubgen.go` (drop orphaned `key` return)
- Modify: `pe/packer/pipeline.go` (use ErrCorruptBlob for non-magic errors)
- Create: `random/int64.go` (`CryptoInt64() (int64, error)`)
- Modify: `pe/packer/stubgen/stubgen.go` + `pe/packer/stubgen/poly/engine.go` (use the new helper)

**Goal:** Three small but accumulating-tech-debt items from the simplify pass.

**Risk:** `Generate`'s signature change is a breaking API change; needs a v0.x.0 bump. Bundle this with whichever next chantier ships its own minor bump.

**Steps:**

- [ ] **Step 1: Generate's `key` return drop (or rename).**

  Decision: rename to `metadata` (struct with seed, rounds, format) so callers have a richer artifact. Existing operators only used `key` for tracking; the new metadata is additive.

- [ ] **Step 2: Pipeline ErrCorruptBlob sentinel.**

- [ ] **Step 3: random.CryptoInt64.**

- [ ] **Step 4: Commit + push as a single API-cleanup commit.**

---

## Self-review — placeholder scan

- ✅ Every step has concrete files to modify
- ✅ Every chantier has its own E2E gate (where applicable)
- ✅ Tag bumps are explicit (v0.62.0 → v0.66.0 over 5 chantiers)
- ⚠️ C3 needs a "Decision required: LZ4 vs custom-inflate vs aPLib" answer before implementation. Operator preference is "no GPL deps" → LZ4.
- ⚠️ C4's "exit_clean" path is hand-waved; the brainstorm session needs to confirm the exact RET target.
- ⚠️ C6 is a brainstorm, not an implementation plan — explicitly deferred to a sub-spec.

## Execution handoff

User chooses execution mode after approving the plan:

1. **Subagent-driven (recommended)** — I dispatch one task per chantier, review between chantiers.
2. **Inline** — execute task-by-task in the current session with checkpoints.
3. **Spread across sessions** — pick + ship one chantier per autonomous session.

Each chantier is self-contained; ordering matters but parallel execution within a chantier is fine.
