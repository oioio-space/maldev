# pe/dllproxy — pure-Go DLL proxy generator — 2026-04-28

Plan to add a new layer-2 package `pe/dllproxy` that emits a valid
Windows DLL **as raw bytes** — no MSVC, no MinGW, no toolchain — given
a target DLL name + its export list. The proxy DLL forwards every
export back to the legitimate target via the "perfect proxy" trick
(`\\.\GLOBALROOT\SystemRoot\System32\<target>.dll.<export>` absolute
path) so the program loading it never knows the difference.

The driving use case is **end-to-end DLL hijacking tests**: the
existing `recon/dllhijack` package finds opportunities, but until now
we had no pure-Go way to *materialise* the DLL that goes into the
hijacked path. `pe/dllproxy` closes that gap.

## References

- `namazso/dll-proxy-generator` — Rust binary tool, BSD-0. The shape we're matching for output. <https://github.com/namazso/dll-proxy-generator>
- `mrexodia/perfect-dll-proxy` — Python script emitting C++ source. Documents the GLOBALROOT trick. <https://github.com/mrexodia/perfect-dll-proxy>
- Microsoft PE/COFF spec (1996 + addenda) — chapter 5 (Image Format), §6.3 (Export Table).
- Existing pe/* siblings: `pe/parse` (export enumeration we'll consume), `pe/srdi` (closest API analog: `ConvertBytes(data, cfg) ([]byte, error)`).

## Status snapshot — going in

| Component | State | Notes |
|---|---|---|
| `recon/dllhijack` | shipped | finds Opportunities (services, processes, tasks, autoElevate) but lacks a payload generator. |
| `pe/parse.Exports()` | shipped | enumerates a target DLL's exports — feeds `pe/dllproxy` directly. |
| `pe/dllproxy` | **not started** | this plan. |

## Composition with existing primitives

```text
recon/dllhijack.ScanXxx ──► []Opportunity
                                  │
                                  ▼
pe/parse.Exports(targetBytes) ──► []string   ← already exists
                                  │
                                  ▼
pe/dllproxy.Generate(targetName, exports, opts) ──► []byte (proxy DLL)
                                  │
                                  ▼
            os.WriteFile(opp.HijackedPath, proxyBytes, 0644)
```

Pure layer-2-to-layer-2 lateral composition. No import cycles.
Cross-platform build (no `_windows.go` — just `pe/dllproxy/dllproxy.go`
+ tests, like every other `pe/*`).

## Conformance audit (skills)

Done up front so future-me on a different machine doesn't redo it.

- **`go-conventions`** — package `dllproxy` (lowercase mono-word, no `_`); types `Options`, `Machine`, `PathScheme` (anti-stutter, no `DllProxyOptions`); `Generate(target string, exports []string, opts Options)` accepts plain types, returns concrete `[]byte`; errors wrapped with `%w` final.
- **`package-design-review`** — `String()` on `Machine` enum (mirrors COFF magic numbers); `String()` on `PathScheme`; no Get-prefix; main type is `Options` (caller supplies, package owns).
- **`go-styleguide`** — config via `Options` struct (matches `srdi.Config` pattern); accept slice / return concrete; document errors; raw strings for the GLOBALROOT path template; no global state.
- **`os-api-correctness`** — N/A (offline emitter, no syscalls).
- **`test-coverage-enforcement`** — round-trip via `pe/parse`: emit, re-parse with stdlib `debug/pe`, assert each export resolves to a forwarder string under `\\.\GLOBALROOT\SystemRoot\System32\<target>.<name>`. One unit test per public symbol. End-to-end on Win10 VM: emit → drop in user-writable opp path → trigger victim → assert the legit target gets loaded transparently.
- **`pre-commit-checks`** — new tech package: README packages table + `docs/persistence.md` cross-ref + `docs/mitre.md` (T1574.001 + T1574.002) + tech md `docs/techniques/persistence/dll-proxy.md`. Run `go run ./cmd/docgen` after the doc.go lands.

## API shape (locked-in for both phases)

```go
package dllproxy

type Machine uint16
const (
    MachineAMD64 Machine = 0x8664 // PE32+, default
    MachineI386  Machine = 0x14c  // PE32, future (phase 3)
)
func (m Machine) String() string

type PathScheme int
const (
    PathSchemeGlobalRoot PathScheme = iota // \\.\GLOBALROOT\SystemRoot\System32\target.dll  — perfect proxy
    PathSchemeSystem32                     // C:\Windows\System32\target.dll                — fallback
)
func (p PathScheme) String() string

type Options struct {
    Machine    Machine
    PathScheme PathScheme

    // PayloadDLL — phase 2 only. When non-empty, the proxy embeds a
    // DllMain that LoadLibraryA's this name on DLL_PROCESS_ATTACH.
    // Phase 1: this field is parsed but errors out as ErrPayloadUnsupported.
    PayloadDLL string
}

// Generate emits a DLL byte stream proxying target's named exports.
//
// targetName is the legitimate DLL name (`version.dll`, `credui.dll`, …).
// exports is the sorted list of exported function names from the target —
// callers typically obtain this via [pe/parse.Exports].
//
// The emitted DLL has no plaintext payload code: every export becomes a
// forwarder pointing at the absolute GLOBALROOT path of the legitimate
// target, so the loading process sees identical behaviour to loading the
// real target — until the optional PayloadDLL kicks in (phase 2).
func Generate(targetName string, exports []string, opts Options) ([]byte, error)
```

## Phase 1 — forwarder-only emitter

**Scope:** ship `Generate(...)` with `Options.PayloadDLL == ""`. No `.text` section, no DllMain, `AddressOfEntryPoint = 0`. The PE spec explicitly allows a DLL with no entry point — Windows simply skips the DllMain call.

**Files:**
- `pe/dllproxy/doc.go` — pkg doc (MITRE T1574.001 + T1574.002, detection very-quiet, See also, Example).
- `pe/dllproxy/dllproxy.go` — single file: constants + types + `Generate` + private emit helpers.
- `pe/dllproxy/dllproxy_test.go` — round-trip + edge cases.
- `pe/dllproxy/dllproxy_example_test.go` — `ExampleGenerate`, `ExampleGenerate_withRealTarget`.

**PE layout (single section):**

```text
File offset 0x000  DOS header (60) + e_lfanew @ 0x3c → 0x40
File offset 0x040  PE signature "PE\0\0"
File offset 0x044  COFF header (20) — Machine=0x8664, NumSections=1, OptHdrSize=240, Flags=0x2022
File offset 0x058  Optional header PE32+ (240)
                     Magic 0x20B; ImageBase 0x180000000; SectionAlign 0x1000; FileAlign 0x200;
                     OS+SubsystemVer 6.0; AddressOfEntryPoint 0; DllCharacteristics 0x0100 (NX_COMPAT);
                     DataDirectory[0]={ rdataRVA, rdataUsedSize }, rest zero.
File offset 0x148  Section header (40) — ".rdata\0\0", flags 0x40000040 (CNT_INITIALIZED_DATA | MEM_READ)
File offset 0x170  pad zero to 0x200 (FileAlignment)
File offset 0x200  .rdata content (variable)
```

**.rdata content (RVA = 0x1000):**

```text
+0       IMAGE_EXPORT_DIRECTORY (40)  Base=1, NumFuncs=N, NumNames=N, AddressOf{Functions,Names,NameOrdinals}, Name → DLL name string RVA
+40      AddressOfFunctions[N]  uint32 each — RVA into .rdata pointing at the forwarder string
+40+4N   AddressOfNames[N]  uint32 each — RVA pointing at the export name string
+40+8N   AddressOfNameOrdinals[N]  uint16 each — `i` (sorted-name → function index identity)
+40+10N  DLL name string  "<targetName>\0"
... then forwarder strings  "\\.\GLOBALROOT\SystemRoot\System32\<target>.<exportName>\0" each
... then export name strings  "<exportName>\0" each (sorted alphabetically per Windows loader binary search)
```

**Forwarder detection rule (MS PE spec §6.3):** an export's RVA is a forwarder iff it points inside the ExportTable data directory range. We size DataDirectory[0].Size to span the *entire* .rdata content used by the export table, so every forwarder string sits inside.

**Round-trip test plan:**

1. `Generate("version.dll", ["GetFileVersionInfoA", ...], Options{})` → `proxyBytes`.
2. `pe.NewFile(bytes.NewReader(proxyBytes))` (stdlib) — must parse without error.
3. For each input export: `f.DynamicSymbols()` (or manual export-table walk) returns the forwarder. We assert the forwarder string equals `\\.\GLOBALROOT\SystemRoot\System32\version.dll.<export>`.
4. Headers sanity: `f.OptionalHeader.(*pe.OptionalHeader64).Subsystem == 2`, `Magic == 0x20B`, ImageBase == 0x180000000.

**E2E test plan (Win10 VM):**

1. Pick a small target, say `version.dll` from System32.
2. `pe/parse.Exports(version.dll)` → `[]string`.
3. `pe/dllproxy.Generate("version.dll", exports, Options{})` → bytes.
4. Drop bytes in `C:\testdir\version.dll`; spawn a process with `cwd=C:\testdir` that calls `GetFileVersionInfoSizeA` (which lives in version.dll).
5. Assert the call succeeds (returns expected length) — proves forwarder reached the real target.

**Estimated size:** ~400-500 LoC in `dllproxy.go`, ~200 LoC tests, ~60 LoC examples + doc.go.

## Phase 2 — DllMain payload load

**Scope:** when `Options.PayloadDLL != ""`, embed:
- `.text` section (16-32 bytes): x64 stub doing `sub rsp,28h; lea rcx,[rip+payload_str]; call qword ptr [iat_LoadLibraryA]; xor eax,eax; inc al; add rsp,28h; ret`. AddressOfEntryPoint points to it.
- `.idata` section: import directory referencing `kernel32!LoadLibraryA`. IAT entry resolved by the Windows loader before DllMain runs.
- Payload-name string in `.rdata` alongside forwarder strings.

**Risks:**
- Import directory layout is finicky (ILT + IAT + name table all separately addressed). Easy to get wrong.
- The `DllCharacteristics` flag `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` would force ASLR + need for relocs — keep it OFF for phase 2 to avoid emitting a `.reloc` section.

**Estimated size:** ~300-400 additional LoC.

## Phase 3 (optional polish)

- i386 (Machine = 0x14C) — different optional header size (224 not 240), no `LARGE_ADDRESS_AWARE`, ImageBase 0x10000000.
- Ordinal-only exports — `<target>.#42` forwarders + `IMAGE_DIRECTORY_ENTRY_EXPORT.NumberOfFunctions` includes ordinals not in name list.
- COM-private exports (`DllRegisterServer`, `DllGetClassObject`, …) — emit with `,PRIVATE` semantics (export ordinal but not name).

## Milestones (resumable across machines)

| # | Milestone | Status | Commit |
|---|---|---|---|
| 1 | Plan committed to docs/superpowers/plans/ | ✅ | `464b9ff` |
| 2 | Skeleton: doc.go + dllproxy.go with stubs + Options/Machine/PathScheme types | ✅ | (folded into 8) |
| 3 | Header emission: DOS + PE/COFF + Optional + section table | ✅ | (folded into 8) |
| 4 | .rdata emission: export directory + forwarder strings | ✅ | (folded into 8) |
| 5 | Round-trip unit test passes on host (Linux) using stdlib debug/pe | ✅ | (folded into 8) |
| 6 | E2E test on Win10 VM with version.dll target | ✅ | TestE2E_VersionDllForwarder PASS |
| 7 | docgen: index.md + mitre.md regenerated; tech md created | ✅ | (folded into 8) |
| 8 | Phase 1 commit + push | ✅ | `4e1f195` |
| 9 | Phase 2: DllMain payload — design notes locked | ✅ | embedded in this plan |
| 10 | Phase 2: .text + .idata emitted, payload load verified on Win10 | ✅ | TestE2E_Phase2_PayloadLoaded PASS |
| 11 | Phase 2 commit + push | ✅ | `bad3cc0` |

## Resuming on another machine

1. `git pull origin master`.
2. Read this file (`docs/superpowers/plans/2026-04-28-pe-dllproxy.md`) — milestone table at the bottom shows where the previous session stopped. Tick a box only when its commit hash is filled in.
3. Read `pe/parse/parse.go` — `Exports()` is the upstream input to `Generate`.
4. Read `pe/srdi/srdi.go` — closest sibling API shape; reuse the `Config`/`Options` patterns and the `ConvertBytes` style entry point.
5. Continue from the first unchecked milestone.

## Out of scope (explicitly)

- 32-bit DLLs (phase 3, low priority — modern Windows targets are x64).
- Self-deleting / sleep-mask integration on the loaded payload — orthogonal, handled by `cleanup/selfdelete` and `evasion/sleepmask`.
- Code-signing the emitted DLL — operator's downstream concern (see `pe/cert`).
- Anti-analysis hardening of the proxy itself (string obfuscation of forwarder paths) — phase 3 candidate.
