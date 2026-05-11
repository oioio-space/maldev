---
status: planning
created: 2026-05-11
last_reviewed: 2026-05-11
---

# Phase 2-F-3-c — Directory Walker Suite Plan

## Why this plan exists

`transform.ShiftImageVA` (shipped 2026-05-11 as v0.103.0
scaffolding, NOT in `RandomizeAll`) bumps every section's
VirtualAddress by a single delta `D`, fixes up:

- Section table VirtualAddress fields
- Optional Header: AddressOfEntryPoint, BaseOfCode, SizeOfImage, SizeOfHeaders
- DataDirectory entry RVAs (top-level)
- Base-relocation table: each block's PageRVA + each entry's
  absolute pointer value

But the kernel rejects the resulting PE with
`STATUS_DLL_NOT_FOUND` (0xC0000135) on real Go binaries because
**internal RVA fields inside the per-directory data structures
remain stale**. The reloc table only covers ABSOLUTE pointers;
RVAs baked as raw uint32 fields by the linker are NOT
relocated.

This plan enumerates the directory walkers needed to make the
shift safe end-to-end and orders them by: required-for-loading
first, required-for-running second, optional-for-tools last.

## Walker inventory

| # | DataDir | Walker | Internal fields to bump | Severity |
|---|---|---|---|---|
| 1 | `IMPORT` (1) | `WalkImportDirectory` | per-descriptor: `OriginalFirstThunk` + `Name` + `FirstThunk` (RVAs); per-thunk-by-name: `Hint/Name` table RVA in each ILT entry whose high bit is clear | **Required for loading.** Without this the loader fails with `STATUS_DLL_NOT_FOUND`. |
| 2 | `EXCEPTION` (3) | `WalkExceptionDirectory` | each `RUNTIME_FUNCTION` (12 bytes): `BeginAddress` + `EndAddress` + `UnwindData` (RVAs); `UnwindData` points at an `UNWIND_INFO` block which may itself contain RVAs to chained handlers | **Required for running.** Go runtime calls `RtlAddFunctionTable`-equivalent; missing handlers crash on first stack unwind. |
| 3 | `LOAD_CONFIG` (10) | `WalkLoadConfigDirectory` | `IMAGE_LOAD_CONFIG_DIRECTORY64`: `LockPrefixTable`, `EditList`, `SecurityCookie` (VA, not RVA — handle separately if reloc'd), `SEHandlerTable`, `GuardCFFunctionTable`, `GuardLongJumpTargetTable`, `DynamicValueRelocTable`, `CHPEMetadataPointer` (PE32+ uses VAs for some, RVAs for others — verify per-field) | **Required for running.** Win10 validates `SecurityCookie` early; CFG-enabled binaries also check `GuardCFFunctionTable`. |
| 4 | `IAT` (12) | implicit via `IMPORT` walker (the IAT array IS the FirstThunk arrays, already covered by #1) | n/a | covered transitively |
| 5 | `EXPORT` (0) | `WalkExportDirectory` | `IMAGE_EXPORT_DIRECTORY`: `Name`, `AddressOfFunctions`, `AddressOfNames`, `AddressOfNameOrdinals` (all RVAs); plus the `AddressOfFunctions` array contents (each entry is an RVA), the `AddressOfNames` array contents (each entry is an RVA to a name string) | Required ONLY when packing DLLs. EXEs typically have no exports. |
| 6 | `RESOURCE` (2) | `WalkResourceDirectory` | recursive tree of `IMAGE_RESOURCE_DIRECTORY` + `IMAGE_RESOURCE_DIRECTORY_ENTRY` + `IMAGE_RESOURCE_DATA_ENTRY` — leaf data entries hold an `OffsetToData` RVA | Required when binary uses `FindResource` etc. (icons, strings). Test fixture `winhello.exe` has empty resources. |
| 7 | `DEBUG` (6) | `WalkDebugDirectory` | each `IMAGE_DEBUG_DIRECTORY`: `AddressOfRawData` (RVA) + `PointerToRawData` (file offset, NOT RVA — leave alone) | Optional for runtime; required for debug-tool consumption. |
| 8 | `BOUND_IMPORT` (11) | `WalkBoundImportDirectory` | offsets relative to the directory itself (NOT RVAs) — leave alone IF directory itself didn't move; verify post-shift the directory is still at its declared RVA (it is — sections don't move data, only declared VAs change) | No-op for VA shift. |
| 9 | `DELAY_IMPORT` (13) | `WalkDelayImportDirectory` | `IMAGE_DELAYLOAD_DESCRIPTOR`: `DllNameRVA`, `ModuleHandleRVA`, `ImportAddressTableRVA`, `ImportNameTableRVA`, `BoundImportAddressTableRVA`, `UnloadInformationTableRVA` (all RVAs) | Rare on Go binaries; required for binaries using `__declspec(dllimport)` with `/DELAYLOAD`. |
| 10 | `TLS` (9) | n/a | `PlanPE` rejects PEs with TLS callbacks before any of this runs. | not reachable |
| 11 | `ARCHITECTURE` (7), `GLOBAL_PTR` (8), `COM_DESCRIPTOR` (14) | n/a | rarely used outside of CLR / IA64; out of scope. | not implemented |

## Implementation order

**Slice 2-F-3-c-2:** ship walker #1 (IMPORT). After this slice the
packed binary loads (passes import resolution). It will still
crash on first SEH unwind because exception data is stale, but
that's a clearer signal to debug than `STATUS_DLL_NOT_FOUND`.

Add an integration test that packs `winhello.exe` with
`RandomizeImageVAShift` + `RandomizeImageBase` ON and asserts
the kernel maps it AND import resolution succeeds (we can detect
this by stub failing during decryption, not at load time). The
Win10 VM E2E will fail at runtime but with a different code than
0xC0000135 — that's the success signal for slice -c-2.

**Slice 2-F-3-c-3:** ship walker #2 (EXCEPTION). After this slice
Win10 VM E2E should PASS for `RandomizeImageVAShift` on
`winhello.exe` (no resources, no exports, no delay imports —
imports + exception is the minimum quorum for a Go static-PIE).

Add `RandomizeImageVAShift` + `RandomizeImageBase` to the
`RandomizeAll` fan-out at this point.

**Slice 2-F-3-c-4:** ship walker #3 (LOAD_CONFIG). Go binaries
emit a load config; CFG validation might trip on stale fields.
Verify by stress-testing on Defender-enabled VM.

**Slice 2-F-3-c-5+:** EXPORT, RESOURCE, DEBUG, DELAY_IMPORT —
order driven by what the real-world payload corpus needs.
Track which payloads fail at which directory and prioritise.

## Walker template

Each walker should expose two functions:

```go
// WalkXxxDirectory(pe []byte, cb func(rvaToPatch uint32) error) error
//
// Read-only enumeration: yields every internal RVA field by its
// FILE OFFSET (not by RVA — caller patches the bytes directly).
// cb signature mirrors the BaseRelocEntry pattern from 2-F-3-a:
// returning a non-nil error stops the walk + propagates.
```

Then the shift path becomes:

```go
WalkImportDirectory(pe, func(rvaFileOff uint32) error {
    cur := binary.LittleEndian.Uint32(out[rvaFileOff:])
    if cur == 0 { return nil } // unset → leave alone
    binary.LittleEndian.PutUint32(out[rvaFileOff:], cur+delta)
    return nil
})
```

Uniform shape across all walkers. Each walker ~60-100 LOC + ~80
LOC tests = ~150-200 LOC per slice. Estimated total: 1000-1500
LOC across 5 slices, ~5-7 commits.

## Why not just disable the directories?

A previous round of brainstorming considered "zero out the
DataDirectory entries the packer doesn't need", e.g. clear
EXPORT, RESOURCE, DEBUG. But:

- IMPORT is required for any non-trivial PE.
- EXCEPTION is required for any Go binary (the runtime walks
  `.pdata` for goroutine stack management).
- LOAD_CONFIG is checked early by the loader on Win10.

So at minimum #1, #2, #3 walkers are non-negotiable.

## Testing strategy

Each walker:
- Unit tests against synthetic minimal PE buffers (mirrors the
  pattern used for `WalkBaseRelocs` in `base_relocs_test.go`).
- Integration test against the real `winhello.exe` fixture:
  call `WalkXxxDirectory` and assert the count of yielded RVAs
  is non-zero (proves the walker found the directory).
- After the IMPORT walker lands, integration tests pack
  `winhello.exe` with `RandomizeImageVAShift` ON and verify the
  result still parses via `debug/pe`.
- After IMPORT + EXCEPTION ship, the Win10 VM E2E test goes
  green for `RandomizeImageVAShift`. This is the gate for
  flipping the `RandomizeAll` fan-out.

## Risks + mitigations

- **DataDirectory[i].VirtualAddress fixup happens in the
  top-level shift code** (already shipped). The walkers operate
  on the directory CONTENTS (the structures the directory's RVA
  points at). The two patches are independent.
- **Some directories overlap sections that have BSS tails**
  (`SizeOfRawData < VirtualSize`). `rvaToFileOff` returns an
  error in that case. The walker should propagate, not silently
  ignore.
- **The shift could push a DataDirectory entry's RVA past the
  end of any section's VA range** if delta is too large. Bound
  delta to `[1, 8] × SectionAlignment` per pack (already done
  in the wiring) so SizeOfImage growth stays small.

## Open questions

- Do CFG (Control Flow Guard) PEs need additional fixup beyond
  `LOAD_CONFIG`'s `GuardCFFunctionTable`? Investigate when the
  walker lands on a CFG-enabled fixture.
- Does Win10's `RtlImageNtHeaderEx` validate any RVA we haven't
  enumerated above? Run with the `LDR` debug stream enabled to
  trace.
