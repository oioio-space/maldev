# Call-stack / Kernel-callback / LSASS-dump — Implementation Plan

> Three independent packages sourced from the 2026-04-24 stargazer/forker
> recon run (see `.recon/stargazer-seen.json` @ `recon/cache` branch).
> Each lands as its own chantier with its own SEMVER bump; phases inside
> a chantier ship as a 4-commit train (scaffold → primitives → public
> API + tests → docs/CHANGELOG + tag).

**Working directory:** `/home/mathieu/GolandProjects/maldev` (master, clean at tag `v0.14.1`).

---

## Ordering rationale

We tackle them cheapest-to-hardest so each chantier can be interrupted or
shipped in isolation:

1. **`collection/lsassdump`** (v0.15.0) — bounded scope, purely user-mode,
   clear MITRE mapping, well-studied primitives. Lowest risk.
2. **`evasion/callstack`** (v0.16.0) — requires x64 unwind-metadata
   manipulation (plan9 asm + `RtlLookupFunctionEntry` synthesis). Medium
   complexity; cleanly composes with existing sleepmask Ekko/Foliage.
3. **`evasion/kcallback`** (v0.17.0) — enumeration-only by default; the
   full removal path depends on a BYOVD driver (out of scope for v0.17.0
   unless we already have one in the closet; otherwise read-only
   enumeration + a design note for the write path).

---

## Package 1 — `collection/lsassdump` (target v0.15.0)

**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory.
**Detection:** **High** (lsass.exe open + full memory read is one of the
loudest events in any modern EDR). Package ships a Caller hook so the
technique composes with `wsyscall` direct/indirect syscalls.
**Inspired by:** `ricardojoserf/NativeDump`, `ricardojoserf/TrickDump`,
`fortra/lsass-shtinkering` (reference only — original IP).

### Scope

- `OpenLSASS(caller) (handle, error)` — `NtGetNextProcess` walk to locate
  lsass.exe (avoids `OpenProcess` path-based hooks), opens with
  `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`.
- `Dump(handle, w io.Writer, caller) error` — writes a MiniDump-format
  blob (MINIDUMP_TYPE = 0x61B = `MiniDumpWithFullMemory |
  MiniDumpWithHandleData | MiniDumpWithThreadInfo | MiniDumpWithTokenInformation`)
  assembled in-process from `NtReadVirtualMemory` chunks — **no call
  to `MiniDumpWriteDump`** (that export is EDR-heavily-hooked).
- `DumpToFile(path string, caller) error` — convenience; writes a
  minidump stream to `path` with 0o600.
- Everything accepts the usual optional `*wsyscall.Caller` so the reader
  can be routed through direct/indirect/NativeAPI syscalls.

### File structure

| Path | Action | Purpose |
|---|---|---|
| `collection/lsassdump/doc.go` | create | Package doc, MITRE, detection |
| `collection/lsassdump/lsassdump.go` | create | Cross-platform types + stubs |
| `collection/lsassdump/lsassdump_windows.go` | create | Real implementation |
| `collection/lsassdump/minidump_windows.go` | create | MiniDump stream builder (pure Go; no dbghelp) |
| `collection/lsassdump/lsassdump_windows_test.go` | create | VM test, admin-gated |
| `docs/techniques/collection/lsass-dump.md` | create | Technique page |
| `docs/mitre.md` | modify | T1003.001 entry |
| `README.md` | modify | collection table row |
| `CHANGELOG.md` | modify | v0.15.0 entry |

### Commit train

- **C1.1** — scaffold (doc.go + stubs + empty tests) — builds on all OSes.
- **C1.2** — minidump stream writer + unit tests (cross-platform, feeds
  handcrafted fake regions; compares against golden bytes).
- **C1.3** — `OpenLSASS` + `Dump` + VM integration test (admin + intrusive
  gates). Test asserts the produced file parses through `debug/minidump`
  standard lib (or a minimal header parser if stdlib lacks one).
- **C1.4** — docs + CHANGELOG + tag `v0.15.0`.

**Risk:** lsass can be PPL on modern Win10/11 with Credential Guard on —
the test will SKIP if `OpenProcess(PROCESS_VM_READ)` returns
ERROR_ACCESS_DENIED even as admin. Documented in `docs/coverage-workflow.md`
as a known SKIP. (Bypassing PPL is a separate future chantier.)

---

## Package 2 — `evasion/callstack` (target v0.16.0)

**MITRE ATT&CK:** T1036 — Masquerading (sub-technique mapping TBD; most
public work cites T1027.007 — Dynamic API Resolution — as a cousin, but
stack-spoofing is its own thing).
**Detection:** **Medium** (walkable synthetic frames look clean unless
the analyst pulls the actual RIP and verifies it against the real unwind
metadata; some EDRs now do cross-check via ETW Threat-Intelligence).
**Inspired by:** `klezVirus/SilentMoonwalk`, `joaoviictorti/uwd`,
`fortra/hw-call-stack`.

### Scope — MVP only

Ship the **synthetic-frame** spoofer (SilentMoonwalk-style), NOT the
full hw-call-stack hardware-breakpoint variant. Hardware version can
land as a follow-up v0.16.1.

- `SpoofCall(addr unsafe.Pointer, args ...uintptr) uintptr` — invokes
  an arbitrary function with a crafted return chain on the stack so
  `RtlVirtualUnwind` walks back through plausible-looking module
  boundaries (kernel32!BaseThreadInitThunk → ntdll!RtlUserThreadStart)
  before hitting our gadget.
- `Frame` — struct { ReturnAddr uintptr; UnwindInfo *RUNTIME_FUNCTION }
  for callers who want to build their own chain.
- `StandardChain()` — returns a pre-built 2-frame chain pointing at the
  standard thread-start sequence. Most callers only need this.
- `WithCallStackSpoof(caller)` — composition hook so `wsyscall.Caller`
  users can route indirect syscalls through a spoofed stack.

### Prerequisites

- Plan9 asm gadget that pivots Rsp into our crafted region, executes
  the target call, restores Rsp. Similar in spirit to the Ekko resume
  stub but purely synchronous.
- Runtime lookup: `RtlLookupFunctionEntry` on `kernel32!BaseThreadInitThunk`
  and `ntdll!RtlUserThreadStart` at package init (cached).
- `RUNTIME_FUNCTION` / `UNWIND_INFO` type definitions (don't pull in
  debug/pe; hand-rolled structs keep the binary lean).

### File structure (sketch)

| Path | Action |
|---|---|
| `evasion/callstack/doc.go` | create |
| `evasion/callstack/callstack.go` | create — types + stubs |
| `evasion/callstack/callstack_windows.go` | create |
| `evasion/callstack/callstack_windows_amd64.s` | create — plan9 asm pivot |
| `evasion/callstack/unwind_windows.go` | create — RtlLookupFunctionEntry wrappers |
| `evasion/callstack/callstack_windows_test.go` | create |
| `docs/techniques/evasion/callstack-spoof.md` | create |

### Commit train

- **C2.1** — unwind-metadata primitives (`RtlLookupFunctionEntry` wrapper +
  `RUNTIME_FUNCTION` types). Tested against well-known addresses.
- **C2.2** — asm pivot gadget + `SpoofCall` MVP (single-frame).
- **C2.3** — `StandardChain()` multi-frame + VM test: spawn a thread
  that sleeps, call `SpoofCall(Sleep, 5s)`, verify an async
  `CaptureStackBackTrace` from a second thread reports
  `BaseThreadInitThunk → RtlUserThreadStart → kernel32!Sleep` rather
  than the real call site.
- **C2.4** — docs + CHANGELOG + tag `v0.16.0`.

**Risk:** plan9 asm + UNWIND_INFO is finicky. Budget a debug spike
similar to the Ekko ROP-chain diagnosis session (memory captured in
`rop_chain_stack_clobbering_diagnosis.md`).

---

## Package 3 — `evasion/kcallback` (target v0.17.0)

**MITRE ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools
(kernel callback removal is the user-mode equivalent of tampering with
EDR's kernel-side telemetry sinks).
**Detection:** **Low** if the removal succeeds cleanly (the EDR stops
getting callbacks — often masquerades as a kernel upgrade or service
hiccup). **High** during the BYOVD driver load (Win10/11 HVCI blocks
unsigned drivers; attested driver list is audited).
**Inspired by:** `V-i-x-x/kernel-callback-removal`, `EDRSandBlast`.

### Scope — enumeration-only in v0.17.0

The FULL removal path requires an arbitrary-kernel-memory-write primitive
(BYOVD or CVE chain). That's its own chantier. For v0.17.0 we ship:

- `EnumProcessNotifyRoutines() ([]Callback, error)` — parses the
  `PspCreateProcessNotifyRoutine` array from kernel memory via an
  existing read primitive. If no read primitive available, returns
  `ErrNoKernelReader`.
- `EnumThreadNotifyRoutines()`, `EnumImageLoadCallbacks()` —
  same pattern.
- `KernelReader` interface so callers can plug in RTCore64, GDRV,
  `\Device\PhysicalMemory` (pre-Win10), or a future driver of their own.
- `Callback` struct: `{Address uintptr; Module string; Enabled bool}`.
  Module name resolved via `EnumDeviceDrivers` + `GetDeviceDriverBaseName`.

The Removal API (`Remove(cb Callback, writer KernelWriter)`) is designed
and documented but marked `// Experimental:` until the driver chantier
lands. Attempting to write will return `ErrReadOnly` if the injected
`KernelReader` isn't a `KernelReadWriter`.

### File structure (sketch)

| Path | Action |
|---|---|
| `evasion/kcallback/doc.go` | create |
| `evasion/kcallback/kcallback.go` | create — types, KernelReader/Writer interfaces |
| `evasion/kcallback/kcallback_windows.go` | create — symbol resolution + enumeration |
| `evasion/kcallback/drivers_windows.go` | create — driver-list → name resolution |
| `evasion/kcallback/kcallback_windows_test.go` | create — uses a mock KernelReader fed from a captured array |
| `docs/techniques/evasion/kernel-callback-removal.md` | create |

### Commit train

- **C3.1** — scaffold + `KernelReader` interface + `Callback` struct.
- **C3.2** — `PspCreateProcessNotifyRoutine` symbol resolution
  (`NtQuerySystemInformation(SystemModuleInformation)` → ntoskrnl base
  + PDB offset; PDB fetched at build or via symsrv at first run, cached).
- **C3.3** — full enumeration + unit tests with mock reader.
- **C3.4** — docs + CHANGELOG + tag `v0.17.0`.

**Risk:** offset of `PspCreateProcessNotifyRoutine` in ntoskrnl shifts
every cumulative update. Ship an embedded offset table for known
ntoskrnl build numbers; fall back to PDB lookup. Document the
freshness-vs-dependency tradeoff in the technique page.

---

## Aggregate estimate

| Package | LOC (est.) | Commits | Phases | VM complexity |
|---|---|---|---|---|
| `collection/lsassdump` | 400 | 4 | straightforward | medium (admin+intrusive) |
| `evasion/callstack` | 600 | 4 | asm-heavy | low (unit-testable) |
| `evasion/kcallback` | 500 | 4 | PDB-heavy | medium (needs live kernel) |

**Total:** ~1,500 LOC across 12 commits + 3 tags, 3 major release docs.

Each chantier keeps the others unblocked: an incident on `callstack` asm
doesn't stop `lsassdump` shipping. Start with C1.1 unless told otherwise.
