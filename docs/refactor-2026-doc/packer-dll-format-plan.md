---
status: planning
created: 2026-05-11
last_reviewed: 2026-05-11
---

# `FormatWindowsDLL` — proper DLL packing plan

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
