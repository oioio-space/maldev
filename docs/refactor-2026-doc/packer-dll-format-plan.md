---
status: pack-time pipeline complete (4 of 4 byte-pipeline slices shipped; LoadLibrary VM E2E deferred to 4.5)
created: 2026-05-11
last_reviewed: 2026-05-11
reflects_commit: HEAD
---

# `FormatWindowsDLL` — proper DLL packing plan

## Slice tracker

| Slice | Surface | Status | Tag |
|---|---|---|---|
| 1 | `transform.PlanDLL` + `Plan.IsDLL` + `ErrIsEXE` + `ImageFileDLL` (promoted to `peconst.go`, dedup'd against `pe/packer/runtime`) | ✅ shipped | v0.110.0 (`a8f66b4`) |
| 2 | `stubgen/stage1/dll_stub.go` — DllMain prologue/epilogue (preserve rcx/edx/r8 + r15, decrypt-once sentinel, tail-call to original DllMain) + `PatchDLLStubDisplacements` + `PatchDllMainSlot`. **Bonus from /simplify:** shared `emitTextBasePrologue` + `patchSentinel` helpers extracted from `EmitStub`/`PatchTextDisplacement` — EXE and DLL paths now share both the CALL+POP+ADD idiom and the sentinel scan-rewrite. | ✅ shipped | v0.111.0 |
| 3 | `transform.InjectStubDLL` — writes encrypted .text, appends the stub section, appends a `.mldrel` section carrying the merged reloc table (host blocks + a new DIR64 entry covering the DllMain slot), re-points `DataDirectory[BASERELOC]`, pre-fills the slot with `ImageBase + OEPRVA`. **Simplify bonus:** the DllMain sentinel + slot patcher moved to `transform` (`DLLStubSentinel`, `DLLStubSentinelBytes`, `PatchDLLStubSlot`); `stage1.PatchDllMainSlot` now wraps it — single source of truth, no cross-package drift. | ✅ shipped | v0.112.0 |
| 4 | `transform.IsDLL` pre-flight + `stubgen.Generate` DLL dispatch + `PackBinary` EXE/DLL cross-check + `stubgen.ErrCompressDLLUnsupported`. Operator-facing API: `PackBinaryOptions.Format = FormatWindowsDLL` now drives the full DLL pipeline end-to-end at the byte level. **Simplify bonus:** the synthetic-DLL test fixture promoted to `testutil.BuildDLLWithReloc` (two consumers); `transform.DirBaseReloc` exported (kills magic-5 in 3 sites). | ✅ shipped | v0.113.0 |
| 4.5 | `LoadLibrary` round-trip on Win10 VM. **Root cause found 2026-05-12:** the stub section was created without `IMAGE_SCN_MEM_WRITE`, so the `mov [r15+flagDisp], al` flag-latch crashed with ACCESS_VIOLATION. Same bug as slice 5.5.x already fixed in `InjectConvertedDLL`. One-line fix in `inject_dll.go:280` (OR `scnMemWrite` into the stub characteristics). Test `TestPackBinary_FormatWindowsDLL_LoadLibrary_E2E` against `testutil.BuildDLLWithReloc` synthetic fixture: PASS. No MSVC dependency needed after all — the synthetic fixture proves the stub structure end-to-end. | ✅ shipped | v0.128.0 |
| 5 | **EXE → DLL conversion** — separate chantier scoped in [`packer-exe-to-dll-plan.md`](./packer-exe-to-dll-plan.md). Converts an EXE input into a DLL output at pack time (sideloading / injection / LOLBAS). Pure-Go pack pipeline, PEB-walk-resolved `CreateThread` to spawn the original OEP from `DllMain(PROCESS_ATTACH)`. 5 sub-slices, ~970 LOC. | ⏳ follow-up | — |
| 6 | **Fused EXE→DLL + dllproxy** — `packer.PackProxyDLL` emits a single DLL that is BOTH a `pe/dllproxy` forwarder for a target system DLL AND a packed-EXE-as-DLL payload. One-file drop for search-order hijack with the payload running on `DllMain(PROCESS_ATTACH)`. Scoped at the end of [`packer-exe-to-dll-plan.md`](./packer-exe-to-dll-plan.md). 3 sub-slices, ~650 LOC. Depends on slice 5. | ⏳ follow-up | — |

## Why this exists

`v0.108.0` rejected DLL inputs at `PlanPE` with
`transform.ErrIsDLL`. That's the SAFE answer ("DLL packing
isn't supported") — not a SOLVED one. This doc scopes the
proper feature so a future contributor can implement
`PackBinaryOptions.Format = FormatWindowsDLL`.

## The core difficulty

A DLL's "entry point" is `DllMain`, called by the loader
**multiple times** with four reason codes:

| Reason code | When | What DllMain should do |
|---|---|---|
| `DLL_PROCESS_ATTACH` (1) | LoadLibrary by first consumer | initialise; return TRUE on success |
| `DLL_THREAD_ATTACH` (2) | every new thread in the host | usually no-op; return TRUE |
| `DLL_THREAD_DETACH` (3) | thread exit | usually no-op; return TRUE |
| `DLL_PROCESS_DETACH` (0) | FreeLibrary or process exit | clean up |

Signature (Windows fastcall ABI):

```
BOOL DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
              ^rcx           ^edx          ^r8
```

Returns BOOL in `eax` / `rax`.

**The existing EXE stub** does:
1. CALL+POP+ADD trick to decrypt `.text` in place.
2. `JMP OriginalEntryPoint` — original `main` runs, eventually
   `ExitProcess` tears down everything.

**For a DLL it must instead**:
1. Be called by the loader with 3 args in rcx/rdx/r8.
2. On `DLL_PROCESS_ATTACH` only: decrypt `.text` (it's the
   first time — subsequent reasons will see decrypted text
   already mapped, so any re-decrypt would corrupt).
3. On EVERY reason: forward control to the original DllMain
   with the original args, return its BOOL return value to
   the caller (the loader), without `ExitProcess`.

## Stub design (~140 bytes)

```asm
; DLL stub. Entry: rcx=hInst, edx=reason, r8=reserved.
; Layout in the appended .mldv section:
;   [stub_start]
;   [decrypted_flag: db 0]         ; 1 byte sentinel
;   [decrypt loop]
;   [trampoline jmp]
;   [original DllMain RVA bytes — patched at pack time]

stub_start:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x20            ; shadow space + alignment
    
    ; preserve args (Windows non-volatile via shadow store)
    mov  [rbp-0x08], rcx
    mov  [rbp-0x10], rdx
    mov  [rbp-0x18], r8
    
    ; check if already decrypted (DLL_PROCESS_ATTACH only)
    cmp  edx, 1
    jne  forward_to_orig_dllmain
    
    ; RIP-relative load of decrypted_flag
    lea  rax, [rip+decrypted_flag]
    cmp  byte ptr [rax], 0
    jne  forward_to_orig_dllmain
    mov  byte ptr [rax], 1
    
    ; ----- standard SGN decrypt loop here -----
    ; (same as EXE stub: CALL+POP+ADD to compute .text base,
    ; iterate through .text decoding each byte, etc.)
    ; -----
    
forward_to_orig_dllmain:
    ; restore args
    mov  rcx, [rbp-0x08]
    mov  rdx, [rbp-0x10]
    mov  r8,  [rbp-0x18]
    
    add  rsp, 0x20
    pop  rbp
    
    ; tail-call to original DllMain — its RET will return our BOOL
    ; to the loader directly.
    jmp  [rip+orig_dllmain_addr]
    
decrypted_flag: db 0
orig_dllmain_addr: dq 0   ; patched at pack time with VA of original DllMain
```

Key points:
- Two RIP-relative loads (`decrypted_flag` + `orig_dllmain_addr`).
  Both within the same `.mldv` section so the offsets are
  constants known at stubgen time.
- `orig_dllmain_addr` is `imageBase + OEP_RVA` at write time —
  but under ASLR + base reloc, this entry needs to be COVERED
  by the .reloc table so the loader rebases it. Means
  appending a base-reloc entry pointing at this address slot.
- Args preserved on the stack with the standard Windows
  prologue (shadow space + non-volatile spill).

## Plan changes required

### `pe/packer/transform/`
- New `PlanDLL(input, stubMaxSize) (Plan, error)` — mirror of
  `PlanPE` but:
  - REQUIRE the `IMAGE_FILE_DLL` bit in COFF Characteristics
    (refuse EXE inputs through this code path).
  - Verify the input has a non-zero OEP (DLL with no DllMain
    is technically valid but pointless to pack).
- `Plan` struct gains `IsDLL bool` flag.
- `InjectStubDLL(input, encryptedText, stubBytes, plan)
  ([]byte, error)` — appends one extra base-reloc entry
  pointing at `orig_dllmain_addr` slot so the loader rebases
  it.

### `pe/packer/stubgen/`
- New `GenerateDLL(opts)` or extend `Generate` to switch
  layout based on `opts.IsDLL`.
- Stub assembler emits the DLL-specific prologue/epilogue
  shown above instead of the EXE `JMP OEP` + `ExitProcess`
  pattern.
- The post-SGN body (after rounds) is the same — only the
  framing differs.

### `pe/packer/packer.go`
- `Format` enum gains `FormatWindowsDLL`.
- `PackBinary` dispatches to `PlanDLL` / `InjectStubDLL` /
  `stubgen.GenerateDLL` when `opts.Format == FormatWindowsDLL`.
- `transformFormatFor` updated.
- `ErrIsDLL` is now an internal sentinel emitted only when
  the input is a DLL but the operator chose `FormatWindowsExe`
  (or `FormatUnknown` and we auto-detected a DLL but they
  wanted EXE semantics).

### Tests
- Unit: synthetic DLL with `IMAGE_FILE_DLL` bit set passes
  `PlanDLL`. EXE with the bit clear fails `PlanDLL`.
- Integration: pack the `testlib.dll` fixture (built in
  today's session), load via `LoadLibrary` from a Go driver,
  call `add(7, 35)` exported by the DLL, assert returns 42.
  Repeat with `RandomizeAll`.
- Build-tag-gated Win10 VM E2E:
  `TestPackBinary_WindowsPE_DLL_*_E2E`.

## Estimated scope

| Component | LOC |
|---|---|
| Stub redesign (`stubgen/dll_stub.go`) | ~250 |
| `transform.PlanDLL` + `InjectStubDLL` | ~200 |
| Unit + integration tests | ~250 |
| Win10 VM E2E + DLL driver | ~150 |
| Tech md updates | doc-only |
| **Total** | **~850 LOC** |

3-5 working sessions.

## What's already shipped that this builds on

- `testlib.dll` + `testlib.c` proof-of-concept (in `ignore/`,
  recipe documented for repro)
- `transform.ErrIsDLL` sentinel — repurposed as the "wrong
  Format selected for DLL input" guard once `FormatWindowsDLL`
  ships.
- All v0.94 → v0.108 Phase 2 randomisation opts — they
  compose with the DLL path unchanged (header mutations don't
  care about EXE vs DLL semantics).

## What this plan deliberately does NOT do

- **No TLS-callback DLL support.** Same reason as the EXE
  path (TLS callbacks run before DllMain — would touch
  encrypted bytes). DLLs with TLS reject early.
- **No DLL with .NET CLR metadata.** Out of scope.
- **No delay-loaded imports inside the DLL.** Would compose
  with the DELAY_IMPORT walker (slice -c-8 in the walker
  plan).

## Why I stopped at the rejection in v0.108.0

Time-budget honest answer: implementing the DLL stub properly
takes 3-5 sessions. Today's session had 12 minutes left when
the question crystallised. Shipping a rejection NOW + a
proper plan for the implementation later is the right
allocation — operators who hit it get a clear message + a
workaround pointer; future-me / next-contributor gets a
fully-scoped plan to implement against.

The rejection is NOT meant to be the final answer.
