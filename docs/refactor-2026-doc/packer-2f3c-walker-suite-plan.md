---
status: planning
created: 2026-05-11
last_reviewed: 2026-05-11
---

# Phase 2-F-3-c — Full Coverage Plan: Walker Suite + Fixture Corpus + E2E Matrix

## ⚡ EMPIRICAL FINDING 2026-05-11 (15:16) — Microsoft CFG binaries are off-limits

Tried packing `C:\Windows\System32\winver.exe` (Microsoft-shipped
PE32+ EXE with full directory inventory: IMPORT + RESOURCE +
EXCEPTION + BASERELOC + DEBUG + **LOAD_CONFIG** + IAT). Results:

  | Pack mode    | Result                                        |
  |--------------|-----------------------------------------------|
  | **vanilla**  | crash `0xC0000409` (STATUS_STACK_BUFFER_OVERRUN) |
  | **RandomizeAll** | "is not a valid Win32 application" (load reject) |

The vanilla pack failing tells us this **isn't a walker
problem** — it's the CFG cookie validation rejecting our
modified `.text` integrity before any user code runs.
Microsoft CFG-protected binaries are out of the operational
envelope regardless of what walkers we ship.

**Implication for plan:** LOAD_CONFIG walker (slice -c-4)
wouldn't help here. CFG-protected binaries need a different
pack strategy (e.g., wrap+exec rather than in-place encrypt)
or simply aren't a supported payload class.

**Documented in tech md as a limitation.** When the user packs
a Microsoft binary and sees `0xC0000409`, they know the
boundary they hit.

---

## ⚡ EMPIRICAL FINDING 2026-05-11 (15:13) — Plan dramatically reduced

Reconnaissance on the actual fixtures (`winhello.exe`,
`winpanic.exe`) shows that **Go static-PIE binaries populate
only 4 DataDirectory entries**:

| Directory | Present in Go static-PIE? | Walker status |
|---|---|---|
| IMPORT (1) | ✅ ~1.4 KiB | ✅ shipped v0.104.0 |
| EXCEPTION (3) | ✅ ~19 KiB (.pdata) | empirically harmless when stale (Go uses pclntab unwinder) |
| BASERELOC (5) | ✅ ~16 KiB | ✅ shipped (base reloc walker) |
| IAT (12) | ✅ same memory as FirstThunk | covered transitively by IMPORT walker |
| **ALL OTHERS** (EXPORT, RESOURCE, LOAD_CONFIG, DEBUG, DELAY_IMPORT, BOUND_IMPORT, TLS, …) | ❌ **empty (RVA=0, Size=0)** | walker not needed for Go targets |

**Conclusion:** v0.104.0 already covers 100% of Go static-PIE
payloads end-to-end. The 7-slice walker suite below is **only
necessary when an operator packs non-Go payloads**: MSVC EXEs
(LOAD_CONFIG), DLLs (EXPORT), GUI apps with resources, apps
using `/DELAYLOAD`, etc.

**Revised strategy:** ship walkers **on-demand**, driven by
real payload failures. Each future slice is gated on:
1. An operator hits a payload that fails RandomizeAll.
2. We capture the failure code (DLL_NOT_FOUND, ACCESS_VIOLATION,
   INVALID_IMAGE_FORMAT, …) and the directory inventory of the
   failing input.
3. Implement only the walker(s) needed to fix that class.

This avoids ~1500 LOC of speculative work that wouldn't move
the needle for the dominant use case. The slice descriptions
below remain as a reference roadmap for when a non-Go payload
demands them.

---

## Why this plan exists (revised — original framing)

`v0.104.0` shipped `RandomizeImageVAShift` in the `RandomizeAll`
fan-out after the IMPORT walker landed. End-to-end test on
`winhello.exe` is green. **But** that fixture exercises only a
subset of the loader-relevant directories — see the at-a-glance
table below. To make `RandomizeImageVAShift` safe across
heterogeneous payloads (Go binaries that panic, MSVC binaries
with CFG, DLLs, GUI apps with resources, etc.) we need:

1. **Every directory walker** that can hold a stale RVA after a
   global VA shift.
2. **A fixture corpus** that exercises each walker's failure
   path before AND after that walker lands.
3. **An E2E test matrix** running pack+execute on every fixture
   so a regression in any walker fails CI loudly.

This document supersedes the previous walker-only plan.

## Why winhello passed with only IMPORT

| Directory | Present in winhello? | Patched in v0.104.0? | Crash trigger when stale |
|---|---|---|---|
| IMPORT (1) | ✅ (97 RVAs) | ✅ | every load — kernel resolves imports first |
| BASERELOC (5) | ✅ | ✅ | every load with non-default ImageBase |
| EXCEPTION (3, `.pdata`) | ✅ | ❌ stale | only on stack unwind / exception / panic / `runtime.Callers` |
| LOAD_CONFIG (10) | ✅ probable | ❌ stale | only if `/guard:cf`, SafeSEH, or RFG enabled |
| EXPORT (0) | ❌ (EXE not DLL) | ❌ | only when consumer calls `GetProcAddress` |
| RESOURCE (2) | ❌ (no icons/strings) | ❌ | only on `FindResourceA` |
| DELAY_IMPORT (13) | ❌ | ❌ | only on first delay-load call |
| DEBUG (6) | ✅ | ❌ stale | runtime fine, debug tools confused |
| BOUND_IMPORT (11) | ❌ | n/a (offsets relative to directory itself) | n/a |
| TLS (9) | ❌ (`PlanPE` rejects) | n/a | n/a |
| ARCHITECTURE (7), GLOBAL_PTR (8), COM (14) | ❌ (rare/legacy) | n/a | n/a |

## Walker inventory

Each walker exposes one function with the same shape as
`WalkImportDirectoryRVAs`:

```go
func WalkXxxDirectoryRVAs(pe []byte, cb func(rvaFileOff uint32) error) error
```

The wiring point in `transform.ShiftImageVA` is identical for
every walker: `+= delta` on each yielded uint32.

| # | Walker | Internal RVA fields | Severity | Slice |
|---|---|---|---|---|
| 1 | IMPORT | descriptor: OFT/Name/FT (×3); ILT+IAT by-name thunks (low 4B of uint64) | required for loading | ✅ shipped 2-F-3-c-2 (v0.104.0) |
| 2 | EXCEPTION | each `RUNTIME_FUNCTION` (12B): BeginAddress, EndAddress, UnwindData (×3 RVAs/entry); UnwindData → `UNWIND_INFO` block which may chain to handler RVAs | required for stack unwind / panic / SEH | 2-F-3-c-3 |
| 3 | LOAD_CONFIG | `IMAGE_LOAD_CONFIG_DIRECTORY64`: SEHandlerTable, GuardCFFunctionTable, GuardLongJumpTargetTable, DynamicValueRelocTable, CHPEMetadataPointer, GuardAddressTakenIatEntryTable, GuardEHContinuationTable (RVAs); SecurityCookie, LockPrefixTable, EditList (VAs — already covered by reloc table if reloc'd) | required for CFG / SafeSEH binaries | 2-F-3-c-4 |
| 4 | EXPORT | `IMAGE_EXPORT_DIRECTORY`: Name, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals (×4 directory RVAs); each entry of AddressOfFunctions array (RVA per export); each entry of AddressOfNames array (RVA per name string) | required only when packing DLLs | 2-F-3-c-5 |
| 5 | RESOURCE | recursive tree: `IMAGE_RESOURCE_DIRECTORY` (header) + `IMAGE_RESOURCE_DIRECTORY_ENTRY[]` (offsets relative to directory base — leave alone) + leaf `IMAGE_RESOURCE_DATA_ENTRY` (`OffsetToData` is an RVA — patch this) | required only when binary uses resources | 2-F-3-c-6 |
| 6 | DEBUG | each `IMAGE_DEBUG_DIRECTORY`: AddressOfRawData (RVA — patch), PointerToRawData (file offset — leave alone) | optional (tools only, runtime unaffected) | 2-F-3-c-7 |
| 7 | DELAY_IMPORT | `IMAGE_DELAYLOAD_DESCRIPTOR`: DllNameRVA, ModuleHandleRVA, ImportAddressTableRVA, ImportNameTableRVA, BoundImportAddressTableRVA, UnloadInformationTableRVA (×6 directory RVAs); same by-name thunk fixup as IMPORT for the IAT/INT arrays | required for delay-loaded DLLs | 2-F-3-c-8 |
| 8 | TLS | `PlanPE` already rejects PEs with TLS callbacks before any of this runs | n/a | not implemented |
| 9 | BOUND_IMPORT | `IMAGE_BOUND_IMPORT_DESCRIPTOR.OffsetModuleName` is relative to the directory itself, NOT an RVA — directory entry's RVA in DataDirectory is patched by top-level shift code, contents need NO walker | n/a | not implemented |

## Test fixture corpus

We need fixtures that EXERCISE each directory's failure mode.
"Exercise" means: at runtime, the binary touches code that
walks the directory in question. Without that, a stale
directory is harmless (the winhello story).

All fixtures live under `pe/packer/testdata/fixtures/` and are
built via a top-level Makefile. Build prerequisites:
- Go (already required; cross-compile to GOOS=windows)
- Windows VM with MSVC (for CFG/C-style binaries)
- `windres` or RC.exe (for resource-bearing binaries)

| Fixture | Builds | Exercises | Pre-walker behaviour | Post-walker behaviour |
|---|---|---|---|---|
| `winhello.exe` (existing) | Go static-PIE: `fmt.Println` then exit | IMPORT + BASERELOC | already PASS | regression check |
| `winpanic.exe` | Go static-PIE: `panic("boom")` then runtime stack unwind | EXCEPTION (.pdata) | crashes during unwind without EXCEPTION walker | clean panic message + exit 2 |
| `wincallers.exe` | Go static-PIE: `runtime.Callers(0, pcs); fmt.Println(pcs)` | EXCEPTION (.pdata) read-only path | crashes or prints empty stack without EXCEPTION walker | prints non-empty stack + exit 0 |
| `wincfg.exe` | C compiled with `cl /guard:cf hello.c` | LOAD_CONFIG (CFG validation) | STATUS_INVALID_IMAGE_FORMAT or crash on first indirect call | clean `printf` + exit 0 |
| `winexports.dll` | C DLL exporting 3 functions, exercised by a tiny driver `winexports_driver.exe` calling LoadLibrary + GetProcAddress | EXPORT | driver gets NULL from GetProcAddress (no walker) | driver prints function results + exit 0 |
| `winres.exe` | C app embedding an icon + version-info via .rc, then calling `FindResourceW(NULL, MAKEINTRESOURCE(IDI_ICON1), RT_ICON)` | RESOURCE | FindResource returns NULL (no walker) | resource handle non-NULL + exit 0 |
| `windelay.exe` | C app with `#pragma comment(linker, "/DELAYLOAD:user32.dll")` then calling MessageBoxA | DELAY_IMPORT | crash at first MessageBoxA call (no walker) | MessageBoxA returns + exit 0 |
| `windbg.exe` | Standard `cl hello.c /Zi /DEBUG` (debug info embedded) | DEBUG (read-only — runtime unaffected) | runtime PASS but `dumpbin /headers` corrupted | runtime PASS + dumpbin clean |
| `winminimal.exe` | C app linked with `/MERGE:.rdata=.text` (single-section, no IMPORT, no relocs) | edge case — `ErrRelocsStripped` rejection path | reject with `transform.ErrRelocsStripped` | same — never reaches any walker |
| `winnpe.bin` | Random bytes 1 KiB | edge case — `parsePELayout` rejection | reject with "missing PE signature" | same |

## E2E test matrix

Each fixture × each pack mode = one Win10 VM E2E test. Build-tag
`maldev_packer_run_e2e` gates them all out of CI; bash harness
runs them via `scripts/vm-run-tests.sh`.

| Fixture | `vanilla` (no opts) | `RandomizeAll` (current 7 opts) | `RandomizeImageBase` alone |
|---|---|---|---|
| `winhello.exe` | PASS (regression) | PASS (regression) | runs but verify exit 0 |
| `winpanic.exe` | PASS — panics → exit 2 | will FAIL pre-2-F-3-c-3, PASS post | same |
| `wincallers.exe` | PASS | will FAIL pre-2-F-3-c-3, PASS post | same |
| `wincfg.exe` | PASS | will FAIL pre-2-F-3-c-4, PASS post | same |
| `winexports.dll` + driver | PASS | will FAIL pre-2-F-3-c-5, PASS post | same |
| `winres.exe` | PASS | will FAIL pre-2-F-3-c-6, PASS post | same |
| `windelay.exe` | PASS | will FAIL pre-2-F-3-c-8, PASS post | same |
| `windbg.exe` | PASS | PASS pre and post (DEBUG is read-only) | PASS |
| `winminimal.exe` | PASS | rejected with `ErrRelocsStripped` | rejected |
| `winnpe.bin` | rejected | rejected | rejected |

Naming convention for the test files:

```
pe/packer/packer_e2e_<fixture>_windows_test.go
  → TestPackBinary_WindowsPE_<Fixture>_Vanilla_E2E
  → TestPackBinary_WindowsPE_<Fixture>_RandomizeAll_E2E
```

## Implementation order — slices with explicit gates

Each slice ships:
1. The walker(s) it owns + unit tests (synthetic fixture).
2. The matching fixture in `testdata/fixtures/` + Makefile rule.
3. New E2E test file(s) for the fixture, asserting both
   `Vanilla` and `RandomizeAll` pass.
4. `/simplify` review of the diff.
5. Tech-md `packer.md` update + commit + push + tag.

### 2-F-3-c-3 — EXCEPTION walker (REPRIORITISED — see empirical finding below)

**Empirical finding 2026-05-11 (15:08):** Built `winpanic.exe`
fixture (Go static-PIE that nil-derefs + recovers via
`defer/recover`). Packed it with `RandomizeAll` (which includes
`RandomizeImageVAShift` since v0.104.0) — **PASSES** without
any EXCEPTION walker. Stale `.pdata` is harmless for Go-built
binaries because Go uses its own pclntab-based unwinder for
panic/recover, NOT Win32 SEH / `RtlVirtualUnwind`.

`.pdata` only matters when:
- Native C/C++ code uses `try/__except` (SEH) — Win32 unwinder
  walks `.pdata`
- Debuggers/profilers call `StackWalk64` from outside the
  process — they read `.pdata`
- The Go runtime walks STD library code that's been linked in
  (rare for static-PIE)

For the typical offensive-packer use case (Go static-PIE
payload that exits cleanly OR panics internally), the
EXCEPTION walker is OPTIONAL defense-in-depth. Reprioritise:

- **Original plan:** -c-3 EXCEPTION first (high priority).
- **Revised plan:** -c-3 demoted to LOW priority. Ship only
  if a C/C++ fixture lights up the failure. Move LOAD_CONFIG
  (-c-4) up to next slice — Win10 validates LOAD_CONFIG
  fields early in the loader, before any user code runs.

- Walker (when shipped): `WalkExceptionDirectoryRVAs` — yields
  BeginAddress, EndAddress, UnwindData per `RUNTIME_FUNCTION`
  (12 bytes each, array length = `directorySize / 12`).
  UnwindData → `UNWIND_INFO` blocks; the variable-length tail
  is one of:
  - 0 bytes if `Flags & 0b111 == 0` (NHANDLER)
  - 4 bytes RVA if `EHANDLER` (1) or `UHANDLER` (2)
  - 12 bytes (full RUNTIME_FUNCTION inlined) if `CHAININFO` (4)
  Recursive walk for chained handlers, depth cap 8 + visited set.
- Fixture (when needed): a C app with a `try/__except` block.
- Tag: v0.105.0 — when shipped.

### 2-F-3-c-4 — LOAD_CONFIG walker

- Walker: `WalkLoadConfigDirectoryRVAs`. Tricky because
  `IMAGE_LOAD_CONFIG_DIRECTORY64` has many fields and Microsoft
  has extended it across Windows versions — newer fields exist
  only when the directory's `Size` field exceeds the older
  layout. Walker yields based on `Size` field (read at offset
  0): patch fields whose offset < Size.
- Fixture: `wincfg.exe` (C + `/guard:cf`).
- E2E gate: fixture passes `RandomizeAll`.
- Estimated scope: ~150 LOC walker + 120 LOC tests.
- Tag: v0.106.0.

### 2-F-3-c-5 — EXPORT walker

- Walker: `WalkExportDirectoryRVAs`. Yields:
  - 4 RVAs in the directory header
  - each entry of AddressOfFunctions (RVA per function entry)
  - each entry of AddressOfNames (RVA per name string)
  - **NOT** AddressOfNameOrdinals entries (those are uint16
    indices, not RVAs)
- Fixture: `winexports.dll` + `winexports_driver.exe` (driver
  packs the DLL with `RandomizeAll`, loads it, calls each
  exported function).
- E2E gate: driver prints expected outputs + exit 0.
- Estimated scope: ~100 LOC walker + 100 LOC tests + DLL/driver
  Makefile rules.
- Tag: v0.107.0.

### 2-F-3-c-6 — RESOURCE walker

- Walker: `WalkResourceDirectoryRVAs` — recursive walk through
  `IMAGE_RESOURCE_DIRECTORY` → `IMAGE_RESOURCE_DIRECTORY_ENTRY[]`
  → either nested directory or leaf `IMAGE_RESOURCE_DATA_ENTRY`.
  Only the leaf's `OffsetToData` field is an RVA; intermediate
  directory entries use offsets relative to the resource
  directory base (NOT RVAs — leave alone).
- Fixture: `winres.exe` (C + .rc embedding an icon).
- E2E gate: fixture passes `RandomizeAll`.
- Estimated scope: ~150 LOC walker (recursion is the cost) +
  150 LOC tests.
- Tag: v0.108.0.

### 2-F-3-c-7 — DEBUG walker

- Walker: `WalkDebugDirectoryRVAs`. Yields one
  `AddressOfRawData` per `IMAGE_DEBUG_DIRECTORY` entry. Skip
  `PointerToRawData` (file offset, not RVA).
- Fixture: `windbg.exe` (existing C app rebuilt with `/Zi /DEBUG`).
- E2E gate: fixture passes `RandomizeAll` AND `dumpbin /headers
  packed.exe` runs without complaint (verified by parsing its
  output for "no errors").
- Estimated scope: ~50 LOC walker + 80 LOC tests.
- Tag: v0.109.0.

### 2-F-3-c-8 — DELAY_IMPORT walker

- Walker: `WalkDelayImportDirectoryRVAs`. Mirrors the IMPORT
  walker shape but on `IMAGE_DELAYLOAD_DESCRIPTOR` (32-byte
  descriptors with 6 RVA fields each).
- Fixture: `windelay.exe`.
- E2E gate: fixture passes `RandomizeAll`.
- Estimated scope: ~120 LOC walker + 100 LOC tests.
- Tag: v0.110.0.

### 2-F-3-c-9 — `RandomizeImageBase` debug + ASLR investigation

- Not a walker. Existing `PatchPEImageBase` + DYNAMIC_BASE
  guard ships in v0.103.0 but fails Win10 E2E with
  intermittent STATUS_ACCESS_VIOLATION. Suspected cause:
  HIGH_ENTROPY_VA flag missing or random base outside
  47-bit user-mode VA. Investigation tasks:
  - Read DllCharacteristics on winhello — is HIGH_ENTROPY_VA
    set?
  - Try restricting `RandomImageBase64` range to the 47-bit
    span (`[0x140000000, 0x7FF40000000)`) — currently goes
    to `0x7FF000000000` which might collide with system
    allocations.
  - Try clearing the `IMAGE_FILE_LARGE_ADDRESS_AWARE`
    Characteristics bit when setting low bases.
  - Investigate Defender interaction with non-canonical
    bases.
- E2E gate: `winhello.exe` passes `RandomizeImageBase: true`
  alone.
- Tag: v0.111.0.

## Definition of Done (overall Phase 2-F-3-c)

Phase 2-F-3-c is "DONE" when:

1. Every walker in the inventory above is shipped + tested.
2. Every fixture in the corpus builds reproducibly via Makefile.
3. Every fixture × `RandomizeAll` E2E passes on Win10 VM.
4. `RandomizeImageBase` joins `RandomizeAll` (or is documented
   as permanently EXPERIMENTAL with rationale).
5. `docs/techniques/pe/packer.md` has a "tested fixtures" table
   listing every supported binary class with a green checkmark.
6. README + `pe/packer/doc.go` mention the supported fixture
   classes so operators know the deployment envelope.

## Estimated scope

| Slice | Walker LOC | Test LOC | Fixture LOC | Total |
|---|---|---|---|---|
| 2-F-3-c-3 EXCEPTION | 120 | 100 | 80 | 300 |
| 2-F-3-c-4 LOAD_CONFIG | 150 | 120 | 50 | 320 |
| 2-F-3-c-5 EXPORT | 100 | 100 | 100 | 300 |
| 2-F-3-c-6 RESOURCE | 150 | 150 | 80 | 380 |
| 2-F-3-c-7 DEBUG | 50 | 80 | 30 | 160 |
| 2-F-3-c-8 DELAY_IMPORT | 120 | 100 | 60 | 280 |
| 2-F-3-c-9 ImageBase debug | n/a | 80 | 0 | 80 |
| **Total** | **690** | **730** | **400** | **~1820** |

7 commits, 7 tags (v0.105.0 → v0.111.0), one fixture-corpus
follow-up commit. Estimated 5-7 working sessions.

## Risk register

- **Walker bugs that pass unit tests but break real PEs.** The
  synthetic-fixture unit tests can miss layout edge cases. The
  Win10 VM E2E is the safety net — every walker must have its
  fixture pass before the slice ships.
- **MSVC build dependency.** Several fixtures need MSVC
  (`/guard:cf`, .rc compilation, /DELAYLOAD pragma). The build
  Makefile must skip these gracefully when MSVC isn't
  available, with a warning that the fixture won't be tested
  on this host. The Win10 VM has MSVC installed (per
  vm-provision.sh), so CI / VM runs are unaffected.
- **`IMAGE_LOAD_CONFIG_DIRECTORY64` versioning.** The structure
  has been extended ~6 times since Win XP. Walker must use the
  `Size` field at offset 0 to know how many fields are
  present; reading past that into "future" fields is fine
  (zero-initialised) but writing past it would corrupt the
  next directory's header. Bound-check carefully.
- **RESOURCE recursion depth.** Pathological PEs could have
  deeply-nested resource trees. Cap recursion at e.g. 8 levels
  to avoid stack overflow on a malicious input; real-world
  PEs are 3 levels deep (Type → Name → Language → Data).

## What this plan does NOT do

- Does not address `RandomizeImageVAShift` on PE32 (32-bit) —
  current code is PE32+ only. PE32 support would be a separate
  slice if/when needed.
- Does not address ARM64 PE binaries — current code assumes
  AMD64 layouts. Would need DIR32 reloc type support + Arm64
  unwind data layout.
- Does not pursue 2-F-3-d (per-section permutation) — still
  blocked on `.text` RIP-relative disassembly. Reconsider
  after 2-F-3-c is fully complete.
