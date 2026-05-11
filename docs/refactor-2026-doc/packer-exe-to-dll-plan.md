---
status: planning
created: 2026-05-11
last_reviewed: 2026-05-11
constraint: pure-Go pack-time (no toolchain, no CGO, no linker, no Go runtime in the stub)
---

# `PackBinaryOptions.ConvertEXEtoDLL` — EXE → DLL conversion plan

## Why this exists

Slices 1–4 of the FormatWindowsDLL chantier let the packer pack a
*native* DLL into a packed DLL. Slice 5 is the more interesting
follow-up: **convert an EXE into a DLL at pack time** so the same
payload can ride into the target as a side-loaded module instead
of a standalone process.

## Operational rationale

| Use case | Why DLL-shaped helps |
|---|---|
| DLL sideloading | Drop the converted DLL next to a signed legitimate EXE that LoadLibrary's it. The payload runs inside the signed host. AppLocker / WDAC bypass surface in certain configs. |
| Classic injection (CreateRemoteThread + LoadLibraryA) | Every textbook injection technique targets DLLs. An EXE-only payload forces operators into reflective-loader gymnastics. |
| Living-off-the-land via `rundll32.exe` / `regsvr32.exe` / `odbcconf.exe` | These loaders only execute DLL exports — they refuse EXE-shaped inputs. |
| Detection lane diversification | An EXE-shaped output triggers different YARA / static-classifier paths than a DLL-shaped one. Same payload, two delivery shapes the operator can choose between. |

The existing `PackBinaryBundle` + `cmd/bundle-launcher` workflow
produces a DLL that LoadLibrary's the unwrapped EXE
**in-memory** — different shape (the EXE binary lives inside the
DLL's `.payload` section, decrypted at runtime). The slice-5
conversion is more aggressive: there is no separate EXE inside;
the EXE's `.text` IS the DLL's `.text`, and the DllMain stub
spawns the EXE's original entry point on a dedicated thread.
One file, no nested binary, smaller surface, no `cmd/bundle-launcher`
intermediary.

## The stub design

EXE-as-DLL stub layout (~350 bytes):

```text
.exe_as_dll_stub_start (= StubRVA):
  ; --- prologue: standard Windows DllMain ABI ---
  push rbp
  mov  rbp, rsp
  sub  rsp, 0x40                ; 0x40 = 6 × 8B + 16 align
  mov  [rbp-0x08], rcx          ; save hInst (= our HMODULE)
  mov  [rbp-0x10], rdx          ; save reason
  mov  [rbp-0x18], r8           ; save reserved
  mov  [rbp-0x20], r15          ; preserve callee-saved

  ; --- CALL+POP+ADD: R15 = textRVA at runtime (shared idiom) ---
  call .after_call
.after_call:
  pop  r15
  add  r15, sentinel(0xCAFEBABE)

  ; --- reason != DLL_PROCESS_ATTACH → forward (return TRUE) ---
  cmp  edx, 1
  jne  .return_true

  ; --- decrypted_flag check (decrypt-once sentinel) ---
  lea  rax, [r15 + flag_disp_sentinel]
  cmp  byte ptr [rax], 0
  jne  .return_true            ; already decrypted, just return TRUE
  mov  byte ptr [rax], 1

  ; --- SGN rounds (shared body with EmitStub / EmitDLLStub) ---
  ; ... for each round[i]: MOVZBQ→subst→MOVB→ADD→DEC→JNZ ...

  ; --- resolve kernel32!CreateThread via PEB walk ---
  ; PEB at gs:[0x60], walk InLoadOrderModuleList until name = "kernel32.dll",
  ; then walk export directory to find CreateThread. We have
  ; pe/packer/stubgen/stage1/fingerprint.go infrastructure for the
  ; PEB walk; need a new EmitResolveKernel32Export helper.
  mov  rax, gs:[0x60]                    ; PEB
  mov  rax, [rax + 0x18]                 ; PEB_LDR_DATA
  mov  rax, [rax + 0x10]                 ; InLoadOrderModuleList.Flink
  ; ... walk to kernel32 entry by Unicode name compare ...
  mov  r12, [rax + 0x30]                 ; kernel32 base → r12
  ; ... walk r12's EAT for CreateThread ASCII name compare ...
  mov  r13, <CreateThread_VA>            ; r13 = CreateThread function pointer

  ; --- CALL CreateThread(NULL, 0, OEP, NULL, 0, NULL) ---
  xor  ecx, ecx                          ; lpThreadAttributes = NULL
  xor  edx, edx                          ; dwStackSize = 0
  lea  r8,  [r15 + oep_disp]             ; lpStartAddress = OEP (absolute VA via R15+disp)
  xor  r9d, r9d                          ; lpParameter = NULL
  sub  rsp, 0x10                         ; shadow space for stack args 5,6
  mov  qword ptr [rsp+0x20], 0           ; dwCreationFlags = 0
  mov  qword ptr [rsp+0x28], 0           ; lpThreadId = NULL
  ; ABI: rcx, rdx, r8, r9 + 32B shadow space + stack-passed args
  sub  rsp, 0x20                         ; standard shadow space
  call r13                               ; CreateThread
  add  rsp, 0x30                         ; restore stack
  ; (rax = HANDLE to spawned thread; we drop it — leaks 1 handle until process exit)

.return_true:
  ; --- restore args + r15 + frame, return TRUE ---
  mov  rax, 1                            ; BOOL TRUE
  mov  rcx, [rbp-0x08]
  mov  rdx, [rbp-0x10]
  mov  r8,  [rbp-0x18]
  mov  r15, [rbp-0x20]
  add  rsp, 0x40
  pop  rbp
  ret                                    ; back to ntdll → loader sees TRUE

; trailing data:
.decrypted_flag:  db 0
```

Key differences from the slice-2 DllMain stub:

1. **No tail-call to an original DllMain** — the input was an EXE,
   there is no DllMain to forward to. Instead `CreateThread(OEP)`
   spawns the EXE's entry point as a parallel thread and we
   immediately return TRUE.
2. **PEB walk to resolve `kernel32!CreateThread`** — we can't link
   against an import because the input EXE doesn't import it
   (and even if it did, we'd be sharing the import table with
   the original — not necessarily desirable). Pure-Go means the
   stub must resolve the API at runtime via the PEB.
3. **Thread leaks its HANDLE** — drop it. The thread terminates
   when the EXE's OEP calls `ExitProcess`, which tears down the
   whole host process. Operationally that's usually what the
   operator wants (sideloaded payload kills the host signed EXE
   when done); if not, the operator gates with `opts.NoExitProcess`.
4. **No reloc entry for the slot** — there's no DllMain VA slot;
   the OEP is referenced as `R15 + oep_disp` (R15-relative,
   same trick as `flag_disp_sentinel`, no absolute pointer).

## Pure-Go constraints (reinforced)

- All asm via `pe/packer/stubgen/amd64.Builder` — no `.s` files,
  no inline assembly via cgo.
- PE mutations via `pe/packer/transform/` byte-native layer.
- Reloc table synthesis: the source EXE may have **no `.reloc`
  section** (Go static-PIE EXEs often don't, since they're not
  relocated by Microsoft's loader the same way). The conversion
  must synthesise a `.reloc` section ex nihilo when the input
  lacks one, since the converted DLL is now subject to ASLR.
- No CGO. No system toolchain. No external linker. No Go runtime
  in the stub (the stub is hand-assembled bytes; the EXE's
  original Go runtime still runs once CreateThread reaches OEP).

## Sub-slice tracker

| Sub-slice | Surface | LOC | Status | Tag |
|---|---|---|---|---|
| 5.1 | `PackBinaryOptions.ConvertEXEtoDLL` + `transform.PlanEXEasDLL` (accepts EXE inputs, returns `Plan{IsDLL: false, IsConvertedDLL: true}` — a new flag distinguishing native-DLL from converted-EXE so stub + injector dispatch correctly). Cross-check in `PackBinary`: refuse `ConvertEXEtoDLL=true` for non-EXE inputs. | ~120 | ⏳ | — |
| 5.2 | `stage1.EmitResolveKernel32Export(b, exportName string)` — generic PEB walk + InLoadOrderModuleList traversal + EAT walk, leaving the resolved function VA in a chosen register. Builds on `stage1/fingerprint.go` (which already walks part of the PEB for CPUID-vendor / build-range checks). | ~200 | ⏳ | — |
| 5.3 | `stage1.EmitConvertedDLLStub(b, plan, rounds)` — DllMain prologue → SGN → resolve CreateThread → spawn → return TRUE. Reuses `emitTextBasePrologue` (shared CALL+POP+ADD), the SGN rounds body, and the decrypted-flag pattern from `EmitDLLStub`. | ~300 | ⏳ | — |
| 5.4 | `transform.InjectConvertedDLL` — clone of `InjectStubDLL` but: (a) sets IMAGE_FILE_DLL on output, (b) flips OptionalHeader DllCharacteristics to include DYNAMIC_BASE, (c) **synthesises a `.reloc` section from scratch** when the input EXE lacks one (Go static-PIE), with one Absolute padding entry if no real relocs are needed. | ~200 | ⏳ | — |
| 5.5 | `stubgen.Generate` dispatch on `ConvertEXEtoDLL` + Win10 VM E2E: pack `winhello.exe` → host harness LoadLibrary's the output → asserts winhello's `"hello"` stdout reached. The harness is a small Go EXE that `LoadLibraryA` then `Sleep(2s)` then exits (the spawned thread writes to stdout meanwhile). | ~150 | ⏳ | — |

Total estimate: ~970 LOC over 5 sub-sessions.

## Tests & validation

Pack-time (Linux, fast):
- `TestPackBinary_ConvertEXEtoDLL_HappyPath` — pack `winhello.exe`,
  parse output with `debug/pe`, assert IMAGE_FILE_DLL set,
  `.reloc` present, entry point at stub RVA, original entry RVA
  reachable via R15+disp.
- `TestPackBinary_ConvertEXEtoDLL_RejectsDLLInput` — convert flag
  + DLL input → error.
- `TestEmitResolveKernel32Export_AssemblesCleanly` — the new
  emitter compiles asm round-trippable through `x86asm.Decode`.

Win VM E2E (slow, real loader):
- `TestPackBinary_ConvertEXEtoDLL_E2E` — build harness, pack
  winhello, run harness, assert stdout contains `"hello"`.
- `TestPackBinary_ConvertEXEtoDLL_PanicE2E` — pack `winpanic.exe`,
  assert the spawned thread's panic/recover still works.

## Out of scope for slice 5

- **DLL → EXE conversion.** The reverse direction is ill-defined
  (a DLL's payload is rarely in DllMain; usually in a named
  export the operator must specify). If/when an operator needs
  this, scope a separate `packer-dll-to-exe-plan.md` with a
  `PackBinaryOptions.DLLEntryExport string` field.
- **TLS callbacks in the source EXE.** Same restriction as the
  EXE path today (`transform.ErrTLSCallbacks`).
- **CFG-protected source EXEs.** Same restriction (cookie
  validation refuses modified .text — empirical finding from
  v0.105.0 winver.exe testing).
- **Compress=true.** Same reason as slice 4
  (`stubgen.ErrCompressDLLUnsupported`); LZ4 inflate doesn't
  thread through the converted-DLL layout in slice 5 v1.
- **Anti-debug prologue.** Easy add later — reuse `emitAntiDebug`
  before the DllMain prologue, same as the EXE stub does. Defer.

## What's already shipped that this builds on

- Slices 1–4 of the native-DLL flow: `PlanDLL`, `EmitDLLStub`,
  `InjectStubDLL`, the shared `emitTextBasePrologue` /
  `patchSentinel` helpers, `testutil.BuildDLLWithReloc`.
- `stage1/fingerprint.go` PEB walking primitives.
- `transform.IsDLL` + `transform.DirBaseReloc` exports.
- `stubgen.ErrCompressDLLUnsupported` model for surfacing
  slice-5 limitations as named sentinels.

## Composition with `pe/dllproxy` — two integration paths

`pe/dllproxy` already emits forwarder-only or forwarder + DllMain
DLLs (see `pe/dllproxy/doc.go` + `assembleWithPayload`). The slice-5
converted-DLL composes with it in two ways:

### Path A — chained (zero new code after slice 5)

```text
packer.PackBinary(winhello.exe, {ConvertEXEtoDLL: true})
                                                   ↓
                                            payload.dll
dllproxy.Generate("version", exports, {PayloadDLL: "payload.dll"})
                                                   ↓
                                            version.dll (proxy)
```

Drop `{version.dll, payload.dll}` in the victim's app directory.
The proxy DLL's DllMain `LoadLibraryA("payload.dll")` triggers our
converted-DLL's DllMain, which decrypts + `CreateThread(OEP)` —
the Go runtime spins up in the host's address space while the
proxy forwards every export back to the real `version.dll`.

**Cost:** zero — emerges naturally from slice 5 + the existing
`dllproxy.Options.PayloadDLL`.

**Drawback:** two-file drop, IAT entry on `kernel32!LoadLibraryA`
in the proxy is a detectable IOC.

### Path B — fused emitter (slice 6)

One file: a single DLL that IS both the proxy AND the packed
payload.

```text
packer.PackProxyDLL(winhello.exe, "version", exports, opts)
                                                   ↓
                                            version.dll (1 file)
```

The output PE contains:

- Export table mirroring the real `version.dll`, with each export
  forwarded via the perfect-dll-proxy absolute path
  (`\\.\GLOBALROOT\SystemRoot\System32\version.<export>`) — taken
  from `dllproxy.buildExportData`.
- Hidden encrypted `.text` of the Go EXE (slice-5 layout).
- `.mldrel` section with the DllMain-slot reloc cover.
- DllMain composed from slice-5 emitter: decrypt-once → resolve
  CreateThread via PEB → spawn the OEP thread → return TRUE.
- **No IAT entry on LoadLibraryA**. CreateThread is resolved at
  runtime via PEB walk (same as slice 5), so the proxy doesn't
  even import kernel32 explicitly.

**Slice 6 sub-slices:**

| Sub-slice | Surface | LOC |
|---|---|---|
| 6.1 | `packer.PackProxyDLL(input, targetName, exports, opts)` — top-level entry point. Coordinates `PlanEXEasDLL` + `dllproxy.buildExportData` + slice-5 stub + new combined injector. |  ~150 |
| 6.2 | `transform.InjectProxyConvertedDLL` — merges what `transform.InjectConvertedDLL` (slice 5.4) does + what `dllproxy.assembleWithPayload` does. Emits one PE with: stub section, .mldrel reloc cover, export-data section (proxy forwarders), and the original .text overwritten with encrypted payload. | ~300 |
| 6.3 | Win VM E2E: pack `winhello.exe` as a `version.dll` proxy → drop in `C:\sideload\` next to a tiny harness EXE that links against `version.dll`'s `GetFileVersionInfoSizeW` → run the harness → assert (a) the harness still gets the real `GetFileVersionInfoSizeW` result (forwarder works), AND (b) `winhello` wrote "hello" to stdout (payload ran on attach). | ~200 |

Total slice 6: ~650 LOC.

## What this plan deliberately does NOT promise

- That every EXE converts cleanly. CFG-protected, TLS-callback-
  bearing, and unusual-runtime EXEs are out of scope (same as
  the EXE pack path today). Operators get a clear error at
  pack time.
- That the converted DLL has the same anti-fingerprint footprint
  as a native DLL. The output is recognisably "an EXE-shaped
  binary with the DLL bit flipped + a synthetic .reloc". Junk
  cover sections, fake imports, and `RandomizeAll` still apply
  and round out the surface — but a determined reverse engineer
  can spot the conversion. Slice 5 ships the capability;
  blending into "natural DLL" shape is a separate research path.
