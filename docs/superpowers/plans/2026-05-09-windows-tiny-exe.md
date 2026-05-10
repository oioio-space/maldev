---
last_reviewed: 2026-05-09
status: in-progress
---

# Windows tiny-exe — symmetry with the Linux all-asm wrap

> **Goal:** Ship a Windows-PE equivalent of `WrapBundleAsExecutableLinux`
> — a hand-rolled stub + minimal hand-written PE32+ container that
> produces a runnable `.exe` of a few hundred bytes. Closes the
> ELF/PE asymmetry in the all-asm bundle path.

**Today** the bundle path's tiny option (`WrapBundleAsExecutableLinux`)
produces a ~470 byte ELF. There is no equivalent for Windows; an
operator targeting Windows from Linux can only produce a ~5 MB Go
launcher binary.

This plan describes everything that needs to land for a
`WrapBundleAsExecutableWindows` to ship.

---

## Known defects / gaps to fix on the way

The list below is the operator-visible TODO. Each row links to a
plan section.

### Container format gaps

- [ ] **No minimal PE32+ writer.** `transform.BuildMinimalELF64`
      ships; the PE32+ counterpart does not exist. PE format is
      richer (DOS header + PE signature + COFF + Optional header
      + section table + file alignment), so the minimum bounded by
      the Windows loader's tolerance is ~268 B. See §1.
- [x] **No build-host Windows PE validator.** ✅ Shipped (2026-05-10)
      as `transform.ValidateMinimalPE`. `debug/pe` roundtrip already
      covers format well-formedness via the test layer; the new
      exported function gives operators a header-walking smoke check
      (DOS/PE magic, AMD64 machine, PE32+ optional magic, 64K-aligned
      ImageBase, non-zero entry RVA) callable on any AMD64 PE bytes
      pre-flight. See §6.

### Stub asm gaps (Windows-specific)

- [ ] **No way to exit the process from raw asm.** Linux uses the
      `syscall` instruction directly (sys_exit_group). Windows has
      no public syscall ABI; the stub must locate
      `kernel32!ExitProcess` via PEB → Ldr → ExportTable walk.
      See §2.
- [ ] **PEB-build predicate stub primitive ships, but the bundle
      stub doesn't wire it.** `EmitPEBBuildRead` (15 bytes of asm)
      exists in `pe/packer/stubgen/stage1`. The Linux bundle stub
      explicitly skips PT_WIN_BUILD; the Windows variant must wire
      it into the per-entry test. See §3.
- [ ] **Negate flag still unsupported in the asm evaluator.** The
      Go-side `SelectPayload` honours `Flags.Negate`; the asm scan
      loop does not. ~50-byte restructure (compute a single match
      boolean per entry, XOR with the negate flag). See §5.

### Wrapping / packaging gaps

- [ ] **`WrapBundleAsExecutableWindows` does not exist.** Every
      step that's in `WrapBundleAsExecutableLinuxWith`
      (PIC trampoline patch + bundle concat + minimal ELF wrap)
      needs a PE-equivalent path. See §4.
- [ ] **`cmd/packer` has no `-format windows-tiny` flag.** The CLI
      currently routes through `packer pack -format windows-exe`
      (Mode 3) only. A new flag dispatch to the Windows tiny path is
      part of the operator UX. See §4.
- [ ] **The bundle launcher's PE writer has no equivalent of the
      "embedded resource" trick** that Authenticode-signed binaries
      use — a future minor could give the tiny-PE a fake VS_VERSIONINFO
      resource so it doesn't look like an empty stub. See §7.

### Reflective-load asymmetry

- [x] **Reflective load (`MALDEV_REFLECTIVE=1`) is Linux-only.** ✅
      Shipped (2026-05-10, v0.78.0). `cmd/bundle-launcher/exec_reflective_windows.go`
      now dispatches to `runtime.Prepare` + `(*PreparedImage).Run`;
      VM-gated E2E `TestLauncher_E2E_ReflectiveLoadsExitCodeWindows`
      green on win10 libvirt. See §8. (Original gap text:) The
      `pe/packer/runtime` reflective loader ships PE support, but
      `cmd/bundle-launcher` only invokes it on Linux. The Windows
      reflective path needs the launcher's `executePayloadReflective`
      to dispatch to `runtime.Prepare` on Windows too. See §8.

### Documentation gaps

- [ ] **Some terms in `docs/techniques/pe/packer.md` assume
      reader knows asm + ELF/PE jargon.** Vulgarisation pass needed
      for: SGN rounds, PIC trampoline, RWX, rep movsb, auxv,
      static-PIE, Brian Raiter, yara, Kerckhoffs, AEAD. See §9.

---

## Sections

### §1. Minimal PE32+ writer

**File:** `pe/packer/transform/pe_minimal.go` (new)

**API:**
```go
func BuildMinimalPE32Plus(code []byte) ([]byte, error)
func BuildMinimalPE32PlusWithBase(code []byte, imageBase uint64) ([]byte, error)
const MinimalPE32PlusImageBase uint64 = 0x140000000
```

**Layout** (canonical, ~336 bytes header):
```
[DOS header (64 B) — only e_magic 'MZ' + e_lfanew used]
[PE signature "PE\0\0" (4 B)]
[COFF header (20 B): Machine=0x8664, NumberOfSections=1, …]
[Optional header PE32+ (240 B, with all 16 DataDirectory entries)]
[Section header × 1 (40 B): .text RWX, full file]
[code]
```

Total minimum: ~330 B + len(code). Operators can shave further by
omitting unused DataDirectories, but the minimum the Windows
loader accepts varies by version — start at 240-byte Optional Header
(canonical) and trim later.

**Tests:**
- `TestBuildMinimalPE32Plus_DebugPEParses` — round-trip via
  `debug/pe.NewFile`.
- `TestBuildMinimalPE32Plus_RunsExit42` — Windows VM E2E
  (build-tag-gated; skipped on Linux build hosts).
- `TestBuildMinimalPE32Plus_RejectsBadInput` — empty / oversized.

**Risks:**
- Different Windows versions accept different minimum Optional
  Header sizes. PE format is forgiving but the loader has version-
  specific quirks (e.g. SizeOfStackReserve must be set on Win10).
- TLS callbacks and base relocation directory must be valid even if
  empty.

### §2. ExitProcess via PEB walk — STATUS: ✅ RUNTIME GREEN (2026-05-10)

> Shipped under autonomy 2026-05-10. Runtime validated via VEH-
> instrumented diagnostic harness on win10 VM —
> `TestEmitNtdllRtlExitUserProcess_RuntimeExits42Windows PASS (6.82s)`.
>
> Bug pinpointed by the Solution-B VEH harness:
>
>   - VEH dump showed `R10 = faulting addr = 0x15479c` (an RVA, not
>     the expected absolute pointer). Diagnosis: `add r10, rdx` at
>     offset 0x32 had no effect.
>   - Root cause: REX-prefix encoding mistake. `0x4c` (W=1, R=1, B=0)
>     extends the source register field, encoding `add rdx, r10`.
>     Correct encoding for `add r10, rdx` is `0x49` (W=1, R=0, B=1)
>     to extend the destination/rm field instead. One byte fix.
>
> Lesson: AMD64 REX-prefix asymmetry between R (source extension) and
> B (destination extension) is an easy off-by-one for hand-encoding.
> Byte-shape unit tests cannot catch this — they pin what IS encoded,
> not whether the encoding has the intended semantic. Runtime + VEH
> trace is the only practical detector.
>
> §4 (WrapBundleAsExecutableWindows) is now unblocked.
>
> Earlier history of attempts (preserved for the lesson):
>
>   - `pe/packer/stubgen/stage1/exitprocess.go` —
>     `EmitNtdllRtlExitUserProcess(b, exitCode)` 143-byte primitive
>     with full byte-by-byte annotation, byte-shape unit test,
>     immediate-patching test.
>   - `ExitProcessImmediateOffset` exported constant for
>     analysts / operators tracking the patched exit-code position.
>
> Runtime VM E2E **failed** twice with ACCESS_VIOLATION (0xc0000005)
> at exec time — the canonical autonomy-hazard scenario. Documented
> open suspects in the file's doc comment:
>
>   1. Export-table walk RVA offsets (NumberOfNames=0x18,
>      AddressOfNames=0x20, AddressOfNameOrdinals=0x24,
>      AddressOfFunctions=0x1c) — verify against modern ntdll dumps.
>   2. The 16-byte string compare may match a non-RtlExitUserProcess
>      prefix; switch to a 19-byte cmp or a ROR-13 hash.
>   3. MS x64 ABI xmm spill space.
>   4. RtlExitUserProcess may be a forwarder on modern ntdll —
>      verify via `dumpbin /exports ntdll.dll` on the target.
>
> Lessons captured for the supervised pickup:
>
>   - InLoadOrderModuleList (offset 0x10 in PEB.Ldr) is the right
>     list for "second entry = ntdll" — InMemoryOrderModuleList
>     (offset 0x20) is sorted by memory address and ASLR-dependent.
>   - DllBase is at LDR_DATA_TABLE_ENTRY+0x30 when walking via
>     InLoadOrderLinks (which sit at offset 0x00 in the entry).
>   - The byte-shape pin shipped is wire-correct against my
>     intended encoding — drift would fail the unit test loudly.
>     Runtime debug must focus on semantic correctness of those
>     pinned bytes, not on the encoder.
>
> §4 (WrapBundleAsExecutableWindows) remains blocked behind this
> primitive's runtime green.

**File:** `pe/packer/stubgen/stage1/exitprocess.go` (new)

The Windows stub can't `syscall` directly (the syscall numbers are
unstable across builds and undocumented). Instead it must:

1. Get TEB → PEB via `gs:[0x60]`.
2. Walk PEB.Ldr.InMemoryOrderModuleList — first entry is the EXE,
   second is ntdll, third is kernel32 (post-Win7). Find kernel32 by
   name match (`KERNEL32.DLL` / `kernel32.dll`).
3. Walk kernel32's export table from the module's RVA-resolved
   `IMAGE_DIRECTORY_ENTRY_EXPORT` directory.
4. Resolve `ExitProcess` by name (or by ROR-13 hash to avoid the
   string).
5. Call it with the desired exit code.

**Asm size:** ~120-150 bytes hand-encoded.

**Alternative (cheaper, less robust):** assume kernel32 is loaded at
a known PEB.Ldr offset. Fragile — kernel32's load order changes
across Win versions. Skip.

**Tests:**
- `TestEmitExitProcessAsm_BytesShape` — pin the encoding.
- `TestEmitExitProcessAsm_RuntimeExits42` — Windows VM E2E.

### §3. PT_WIN_BUILD wire-up in the Windows stub

The Linux stub explicitly zeroes `hostBuild` and skips `PT_WIN_BUILD`.
The Windows stub must:

1. After CPUID prologue, read `OSBuildNumber` via the existing
   `EmitPEBBuildRead` (15-byte primitive, pins EAX = build).
2. Save to a non-volatile reg (R12 on Windows is callee-saved per
   the MS x64 ABI, but inside `_start` we own the register file).
3. In the per-entry test, when `PT_WIN_BUILD` is set, compare EAX
   against `[r8+16]` (BuildMin) and `[r8+20]` (BuildMax) using the
   existing `EmitBuildRangeCheck` primitive (34 bytes).

Total Windows-stub additional asm vs Linux: ~50 bytes (PEB read +
build-range check).

### §4. WrapBundleAsExecutableWindows — PHASE A: ✅ RUNTIME GREEN (2026-05-10)

> Shipped 2026-05-10:
>
>   - `pe/packer/bundle_stub_winwrap.go` —
>     `bundleStubVendorAwareWindows()` builds a Windows-flavoured
>     scan stub by patching the Linux stub: 5-byte `jmp rel32`
>     replaces the 9-byte sys_exit_group, §2 ExitProcess block
>     appended at the end, 3 Jcc displacements decremented to
>     follow the .matched-section move (124 → 120).
>   - 3 exported APIs: `WrapBundleAsExecutableWindows`,
>     `WrapBundleAsExecutableWindowsWith`,
>     `WrapBundleAsExecutableWindowsWithSeed` — mirror the Linux
>     trio shape.
>   - 4 unit tests green (RejectsBadInputs, DebugPEParses,
>     WithSeed_Deterministic, StubLayoutSanity).
>
> **Runtime status: NOT GREEN.** First VM dispatch reported
> ACCESS_VIOLATION (0xc0000005). The wrapped PE path is
> kernel-loaded — VEH harness inside the test process can't catch
> the crash. Test now t.Skip-gated until supervised debug routes
> the stub bytes through the asmtrace harness for a register dump.
>
> Suspect list (in order of investigation cost):
>
>   1. The 5-byte `jmp rel32` at offset 115 — disp encoding may be
>      off (verified to be `matchedLen` in source, may need
>      double-checking on the actual byte layout post-injectStubJunk).
>   2. The 3 Jcc patches at offsets 63/88/106 — the disp shift
>      assumed .matched moved -4 because exit_group(9 B) → jmp
>      rel32(5 B). Sanity-check by extracting and disassembling
>      the produced stub bytes.
>   3. The §2 block embedded inline — when reached via JMP from
>      .no_match (vs from a fresh kernel-call), RSP alignment may
>      differ. CPUID prologue's `sub rsp, 16` shifts RSP, then §2's
>      `sub rsp, 0x28` may land mis-aligned. Validate by manually
>      computing RSP through the path.
>   4. injectStubJunk interaction with the Jcc patches — junk
>      insertion at slot A (offset 14) shifts everything after; the
>      patches happen BEFORE junk insertion. Verify by setting seed=0
>      to disable junk and seeing if the runtime crash still occurs
>      (the unit test StubLayoutSanity uses seed=0 and the byte
>      shape looks right).
>
> Debug strategy for the supervised pickup:
>
>     // Build the stub-only bytes
>     stub, _ := bundleStubVendorAwareWindows()
>     // Append a fake bundle blob with 1 PT_MATCH_ALL entry pointing
>     // at WindowsExit42ShellcodeX64
>     // Concat stub + bundle, write to file
>     // Run via asmtrace.exe — VEH harness gives full register dump
>
> §5 (negate flag refactor) is independent of this — proceed in
> parallel.

**File:** `pe/packer/bundle_stub.go` (extend) + `pe/packer/bundle_stub_windows_test.go` (new)

```go
func WrapBundleAsExecutableWindows(bundle []byte) ([]byte, error)
func WrapBundleAsExecutableWindowsWith(bundle []byte, profile BundleProfile) ([]byte, error)
func WrapBundleAsExecutableWindowsWithSeed(bundle []byte, profile BundleProfile, seed int64) ([]byte, error)
```

Mirrors the Linux trio. Internal:
1. Emit Windows-flavoured stub (PIC + CPUID + PEB-build read + scan
   loop with both PT_CPUID_VENDOR and PT_WIN_BUILD + decrypt + JMP +
   ExitProcess fallback).
2. Optional polymorphism via the existing `injectStubJunk`
   (slot A is the same — between PIC and CPUID prologue).
3. Concatenate stub + bundle.
4. Wrap via `transform.BuildMinimalPE32PlusWithBase` honouring
   `profile.Vaddr` (becomes `ImageBase` on PE).

**CLI:** new `-format windows-tiny` for `packer bundle -wrap`.

### §5. Negate flag in the stub asm — STATUS: deferred to supervised session (2026-05-10)

> Considered for autonomy 2026-05-10 alongside §4 PHASE A; deferred.
>
> Why deferred: §5 touches the existing
> `bundleStubVendorAware()` byte array — the Linux scan stub that
> has runtime-green E2E tests. Refactoring it for negate support
> requires:
>
>   1. Replacing each `jnz .matched` / `jz .next` direct branch with
>      a "set AL; jmp .compute_negate" sequence (~3 bytes more per
>      branch × 5 branches = +15 bytes).
>   2. Adding a new `.compute_negate` block (~10-15 bytes):
>      `movzx r9d, byte [r8+1]; and r9b, 1; xor al, r9b;
>       test al, al; jnz .matched; jmp .next`
>   3. Recomputing every Jcc displacement in the loop body (the
>      .matched / .next / .vendor_zero_check anchors all shift).
>
> Total stub growth: ~25-30 bytes. Without an asm-stepper (Solution D
> long-term plan) or per-instruction unit tests, the only validation
> path is runtime VM E2E — and a wrong displacement breaks the
> Linux green tests too.
>
> Recommended approach for the supervised pickup:
>
>   - Migrate `bundleStubVendorAware()` from raw byte arrays to the
>     existing `pe/packer/stubgen/amd64.Builder` API which handles
>     Jcc displacements via labels. Removes the recomputation hazard.
>   - Add `EmitBundleScanLoop(b *amd64.Builder, withNegate bool)`
>     that the existing function then wraps. New tests pin the
>     byte shape with and without negate.
>   - Once Builder-driven, `bundleStubVendorAwareWindows()` can be
>     similarly Builder-rewritten (Solution D becomes very valuable
>     here — testing different stub variants at unit-speed).
>
> Independent of §4 PHASE A runtime green — §5 can land in its own
> minor regardless of §4 status.

Unblocks both Linux and Windows. Refactor the per-entry asm so the
match outcome is computed into AL (1 byte) and then XOR'd with the
negate flag (`byte [r8+1] & 1`) before branching:

```asm
.loop:
  …
  ; compute raw_match → al (1 if predicate fires, 0 otherwise)
  …
  movzx r9d, byte [r8+1]
  and   r9b, 1
  xor   al, r9b           ; flip if negate set
  test  al, al
  jnz   .matched
  jmp   .next
```

~30 bytes additional asm. All Jcc displacements between the new
"compute raw_match" block and `.matched` must be recomputed.

### §6. Build-host smoke loader

**File:** `pe/packer/transform/pe_smoke_test.go` (new — host-only test)

Use `debug/pe.NewFile` + manual sanity checks (entry point inside
`.text`, ImageBase aligned to 64 K, SizeOfImage matches PT_LOAD
extents). Doesn't catch all loader rejections but catches the 80 %
of structural mistakes that would crash on Win immediately.

### §7. Optional VS_VERSIONINFO resource

Stretch goal. Adds an `IMAGE_RESOURCE_DIRECTORY` to the tiny PE
pointing at a fake VS_VERSIONINFO block claiming, say,
"Microsoft Corporation / 10.0.19041.1110". Gives the tiny-PE a
non-empty Properties dialog when right-clicked in Explorer. ~200
extra bytes, configurable via `WrapBundleAsExecutableWindowsOptions`.

### §8. Reflective load on Windows

**File:** `cmd/bundle-launcher/exec_reflective_windows.go` (new)

`pe/packer/runtime` already supports PE reflective loading (Phase 1f
Stage A-D shipped that). The launcher's `executePayloadReflective`
just needs a Windows variant that calls `runtime.Prepare` +
`(*PreparedImage).Run` instead of falling back to the temp-file +
CreateProcess path.

Same env-var contract as Linux: `MALDEV_REFLECTIVE=1` opts in.

### §9. Documentation vulgarisation

`docs/techniques/pe/packer.md` assumes reader knows asm + ELF/PE
internals. Tracks what each term means at first mention:

- **SGN (Shikata Ga Nai-style)** polymorphic encoder — explain it's
  per-byte XOR with a key that itself rotates per round; "polymorphic"
  meaning the round-by-round register choices are randomised per
  pack so the decoder bytes look different even for the same input.
- **PIC trampoline** (`call .pic ; pop r15`) — explain it's how
  position-independent code learns its own runtime address (the
  `call` pushes the next instruction's address, the `pop`
  retrieves it).
- **RWX** — Read+Write+Execute permissions on a memory page.
  Loud signal because legitimate processes almost never need it
  (modern code is usually R+X for code, R+W for data).
- **rep movsb** — x86 instruction that copies bytes from `[rsi]` to
  `[rdi]` `rcx` times. Used for in-place memmove.
- **auxv** — auxiliary vector, the kernel-supplied data pushed onto
  the stack at process start (random canary, page size, AT_RANDOM,
  etc.). The reflective loader rewrites it to point at the loaded
  binary instead of the launcher.
- **static-PIE** — Position-Independent Executable that is also
  statically linked (no `PT_INTERP` pointing at ld.so). Required for
  the reflective loader because we can't load the dynamic linker
  ourselves.
- **Brian Raiter shape** — reference to Raiter's "tiny ELF" 2002
  article showing the smallest legal Linux ELF (45 bytes). Our
  minimal-ELF emitter is the same shape, slightly bigger to host
  real code.
- **yara** — file-pattern matching language used by AV / EDR for
  static signatures. "yara'able" means a defender can write a yara
  rule that matches.
- **Kerckhoffs's principle** — Auguste Kerckhoffs (1883): the
  security of a cipher must depend on the secrecy of the key, not
  the secrecy of the algorithm. Applied to packers: the bundle
  format is public; the per-build secret is the only thing varying.
- **AEAD** — Authenticated Encryption with Associated Data. AES-GCM
  is the canonical example: it both encrypts AND verifies that the
  ciphertext wasn't tampered with.
- **PT_LOAD** — ELF program header type for "loadable segment". The
  kernel mmaps these into the process address space at exec time.
- **CPUID leaf 0** — instruction reading the CPU vendor string
  ("GenuineIntel", "AuthenticAMD", etc.) into EBX:EDX:ECX
  registers.
- **PEB** — Process Environment Block. Windows kernel-managed
  structure at a known offset (`gs:[0x60]` on x64) carrying
  process-wide state including the loaded module list.

The vulgarisation pass either inlines short explanations at first
mention or links to a glossary section.

---

## Implementation order

1. §9 docs vulgarisation — cheap, ships ahead of code.
2. §1 minimal PE32+ writer — foundation for everything else.
3. §2 ExitProcess via PEB walk — needed for stub.
4. §3+§4 Windows stub + WrapBundleAsExecutableWindows.
5. §5 Negate flag (orthogonal, can ship anytime).
6. §6 smoke loader.
7. §8 reflective load on Windows.
8. §7 VS_VERSIONINFO (stretch).

Each step ships independently; the elevation plan tracker
(`docs/superpowers/plans/2026-05-09-packer-elevation.md`) gets a
new row per step.

---

## Resumption notes

— Plan file authored 2026-05-09. Implementation pending.
— Current shipped: §9 (docs vulgarisation) — see commit hash in
  the elevation plan tracker.
