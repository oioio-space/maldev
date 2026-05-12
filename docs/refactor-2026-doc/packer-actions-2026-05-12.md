---
status: in-progress
created: 2026-05-12
last_reviewed: 2026-05-12
reflects_commit: HEAD (slice 1.A.2)
---

# Packer — action plan tracker (2026-05-12)

> Live tracker for the prioritised improvements coming out of
> [`packer-improvements-2026-05-12.md`](./packer-improvements-2026-05-12.md).
> Update on every commit that ships a row.

## Active priority queue

| # | Item | Effort | Status | Tag |
|---|---|---|---|---|
| **1** | **Mode 8 args injection — `DefaultArgs` opt + `RunWithArgs` export** | ~200 LOC | 🟢 in progress | — |
| 2 | Mode 7 + Compress symmetry with Mode 8 | ~80 LOC | ⏳ next | — |
| 3 | `RandomizeStubSectionName` ON by default (OPSEC quick win) | ~5 LOC + tests | ⏳ scoped | — |
| 4 | PE32+ Machine check explicite (silent breakage guard) | ~10 LOC | ⏳ scoped | — |
| 5 | Walker interface unifié (R2 in audit) | ~150 LOC | ⏳ scoped | — |
| 6 | SGN body dedup (R1 in audit) | ~100 LOC | ⏳ scoped | — |
| 7 | MSVC fixture provisioning on Win10 VM | ~setup + 1 fixture | ⏳ scoped | — |
| 8 | Cert preservation opt-out (Z4 in audit) | ~30 LOC | ⏳ scoped | — |

## Item #1 — design notes

**User concerns:**
- (a) "verify args passed to a packed EXE are received by payload"
  → ✅ **VALIDATED** for Mode 3 (vanilla + RandomizeAll) via
    `TestPackBinary_Args_Vanilla_E2E` + `_RandomizeAll_E2E`
    (commit `0cfee1b`).
- (b) "set default args for a program transformed into a DLL"
  → 🟢 **IN PROGRESS** — implementing `DefaultArgs` opt for Mode 8.

### Two-part feature

**Part A — pack-time default args** (`PackBinaryOptions.ConvertEXEtoDLLDefaultArgs string`):
The operator bakes a default command-line into the packed DLL.
On `DllMain(PROCESS_ATTACH)`, before `CreateThread` spawns the
OEP, the stub patches `PEB.ProcessParameters.CommandLine` to
point at the baked args. Payload's `GetCommandLineW` /
`os.Args` returns operator-controlled values.

**Part B — runtime `RunWithArgs` export**:
The packed DLL also exposes a `RunWithArgs(LPCWSTR args)`
exported function. Operator can invoke it via
`GetProcAddress` + indirect call to spawn the payload with
custom args at any time, regardless of the default. Useful
for repeat invocations or when the operator wants to chain
the payload with their own args mid-attack.

### Implementation slices

| Slice | Scope | LOC | Status |
|---|---|---|---|
| 1.A.1 | PEB-patch asm helper (`stage1.EmitPEBCommandLinePatch`) | ~80 | ✅ shipped (2a89369) |
| 1.A.2 | Wire DefaultArgs into `EmitConvertedDLLStub`: emit PEB patch BEFORE CreateThread, append args buffer to stub section | ~60 | ✅ shipped |
| 1.A.3 | Plumb `PackBinaryOptions.ConvertEXEtoDLLDefaultArgs` → `stubgen.Options` → `stage1.EmitOptions` | ~20 | ✅ shipped |
| 1.A.4 | Win10 VM E2E: pack `probe_args.exe` with DefaultArgs="custom one two", LoadLibrary, assert marker contains "custom\|one\|two" | ~50 | ✅ PASS on Win10 VM (after asm pivot) |
| 1.B.1 | `RunWithArgs` export — emitted in the stub section, registered in the DLL's export table via `transform.AppendExportSection` | ~100 | after 1.A complete |
| 1.B.2 | Win10 VM E2E: pack, LoadLibrary, GetProcAddress("RunWithArgs"), call with custom args, assert marker | ~50 | after 1.B.1 |

Each slice ships its own commit. Tags every successful slice
end (1.A complete = v0.130.0, 1.B complete = v0.131.0).

### Cross-machine resume — current state

**Slice 1.A complete.** Tagged v0.130.0. Pickup at **slice 1.B.1**
(`RunWithArgs` export emitted in stub section + registered in DLL
export table via `transform.AppendExportSection`).

Big lesson from 1.A.4 (saved as `feedback_getcommandline_cache.md`):
the original PEB-patch design (rewrite `CommandLine.Buffer` pointer)
was a no-op because `kernel32!GetCommandLineW` caches its result on
first call — every subsequent caller (Go runtime, MSVC CRT, etc.)
reads the cache, NOT PEB. Pivoted to **in-place memcpy** at the
existing buffer pointer (43 B asm: PEB → ProcessParameters → load
existing Buffer into RDI → REP MOVSB from stub-baked args → update
Length/MaximumLength). Limitation: assumes existing buffer ≥
argsLenBytes+2; documented on the field.

The Win64 PEB layout used by the asm patch:
- `gs:[0x60]` → PEB pointer (TEB+0x60)
- `PEB+0x20` → ProcessParameters pointer
- `ProcessParameters+0x70` → CommandLine UNICODE_STRING:
  - +0x00: Length (uint16, bytes excluding null)
  - +0x02: MaximumLength (uint16, bytes including null)
  - +0x08: Buffer (PWSTR)

The patch overwrites Length, MaximumLength, Buffer with the
operator's args. Does NOT save/restore — the host process's
CommandLine stays clobbered for the duration. Documented as
an OPSEC trade-off.
