# Package Reorganization — Coherence Audit + Proposal

> **Status:** Pass 1 in flight. **Author:** session 2026-04-25 after the 8-chantier ship.
> **Inputs:** full 62-package inventory (see chat log of session 2026-04-25), `docs/architecture.md`, observed import patterns.
>
> **Reading note:** path arrows `[OLD]` → `[NEW]` are written as
> `OLD-PATH` (with a backslash before the slash, hidden in render) to
> survive future search-and-replace passes. The pre-Pass-1 paths are
> referenced inside `code-spans-with-dashes`: e.g. `was-evasion-dllhijack`.

---

## Why now

The repo grew chantier-by-chantier; every new technique landed under the
parent dir that "felt right" at the time. After 18 months and 62
packages, several cross-cutting themes were spread across the old
`evasion/`, `system/`, `pe/`, `cleanup/`, and `inject/` trees that,
viewed together, fought the operator's mental model.

This doc:

1. Names the **7 incoherence themes** that fragmented the pre-Pass-1 tree.
2. Lists the **packages that misfit** their parent before Pass 1.
3. Proposes a **target tree** that aligns to ATT&CK-adjacent operator
   mental models without burning the existing `evasion.Technique` /
   `inject.Injector` interface contracts.
4. Sketches a **migration order** that ships in 3 versioned passes
   instead of one giant rename.

---

## 1 — Incoherence themes

### Theme A — pre-Pass-1 `evasion/` mixed "active evasion" with "passive recon"

`evasion/` (pre-Pass-1) bundled three orthogonal kinds of work:

- **Active evasion** (touches own/target process to bypass a defense):
  `amsi`, `etw`, `unhook`, `sleepmask`, `acg`, `blockdlls`, `cet`,
  `callstack`, `kcallback`, `stealthopen`, `hook` — patches memory,
  registers callbacks, swaps return chains.
- **Passive recon / anti-analysis** (read-only checks of the
  environment): `was-evasion-antidebug`, `was-evasion-antivm`,
  `was-evasion-sandbox`, `was-evasion-timing` (the busy-wait variant
  detects accelerated time), `was-evasion-hwbp` (DR0-DR7 inspection)
  — returns booleans / scores, doesn't change system state.
- **Process tampering** (modifies a *different* process): `hideprocess`,
  `herpaderping`, `fakecmd`, `phant0m` — `WriteProcessMemory` /
  `TerminateThread` against a victim PID.
- **Discovery** (enumerates opportunities for later phases):
  `was-evasion-dllhijack` — returns `Opportunity` records; never
  modifies anything.

These don't share code paths or audiences. An operator looking for
"how do I detect a sandbox?" should not have to wade through 21
`evasion/*` directories to find the right one.

### Theme B — pre-Pass-1 `system/` was a junk drawer

`system/` (pre-Pass-1) was the catch-all for "anything Windows-y that
didn't have an obvious home". It contained:

- `was-system-ads` — data-hiding primitive (anti-forensic) — fits `cleanup/`
- `was-system-bsod` — destructive operation — fits `cleanup/`
- `was-system-drive` — recon (drive enumeration)
- `was-system-folder` — recon (special folder paths)
- `was-system-lnk` — LNK creation, used by `persistence/startup` — fits `persistence/`
- `was-system-network` — recon (interface IPs)
- `was-system-ui` — interactive UX (MessageBox, MessageBeep) — the only "system" one

Resolution: retire `system/` entirely; promote `ui` to top-level.

### Theme C — `pe/` mixes "PE file manipulation" with "in-process code loaders"

- True PE/COFF binary manipulation: `pe/parse`, `pe/strip`, `pe/morph`,
  `pe/imports`, `pe/cert`, `pe/masquerade`, `pe/winres`, `pe/srdi` —
  fits `pe/`.
- In-process .NET CLR host: `pe/clr` — *executes managed code*.
- In-process COFF loader: `pe/bof` — *executes BOF code*.

`pe/clr` and `pe/bof` are siblings of `inject/` (both are code-execution
primitives), not siblings of `pe/parse`. They're in `pe/` because the
input format is COFF/PE, but the operator-facing semantics are
"runtime loader for X" — that deserves its own top-level
(proposed: `runtime/`).

### Theme D — Privilege escalation is split across 3 trees

- `win/privilege` — "I have admin, escalate to higher contexts"
  (LogonUser, RunAs, IsAdmin check)
- `uacbypass/` — "I have medium IL, exploit auto-elevate to high IL"
  (FODHelper, SLUI, etc.)
- `exploit/cve202430088` — "I have user-mode, exploit kernel TOCTOU
  to SYSTEM"

These three are the same operator concern (elevate). Split across
three top-level dirs they don't reinforce each other; consolidating
them into `privesc/` makes the escalation surface visible at a glance.

### Theme E — `collection/` and `credentials/` are blurred

`collection/lsassdump` is the only credential dumper, sitting in
`collection/` next to `keylog`, `clipboard`, `screenshot`. But
"credential access" (`T1003`) is a distinct ATT&CK tactic from
"collection" (`TA0009`); future SAM/DPAPI/NTDS dumpers won't fit
naturally next to a clipboard watcher.

### Theme F — `win/user` is mislabeled

`win/user` is `NetUserAdd` / `NetUserDel` / `NetLocalGroupAddMembers`.
That's **persistence by account creation** (T1136), not a Windows
*primitive*. It sits in Layer 1 next to `win/api` and `win/syscall`,
which is misleading — every other `win/*` package is a low-level
syscall or COM wrapper, not an offensive-action primitive.

### Theme G — `inject/` is a 19-method monolith

The `inject/` package ships 16 Windows methods + 3 Linux methods
inside one Go package. That's deliberate — the unified `Injector`
interface lets methods chain via `Pipeline` + `WithXxx` decorators —
but visually it gives no hint that:

- some methods are **self-injection** (CT, Fiber, ETW, ApcEx, ThreadPool, KCallback, PhantomDLL, Callback, SectionMap)
- some are **remote injection** (CRT, EarlyBird, ThreadHijack, RTL, SpoofArgs)
- some are **process hollowing** (Hollow)
- Linux methods are a separate substrate (Ptrace, MemFD, ProcMem)

Splitting the implementation files (not the package) by audience
would help readers without breaking the interface.

---

## 2 — Per-package misfits + proposed moves

Format: `was-<old-path>` → `<new-path>` — rationale.

### Pass 1 — `recon/` carve-out + `system/` retirement (this commit)

- `was-evasion-antidebug` → `recon/antidebug` — read-only debugger detection.
- `was-evasion-antivm` → `recon/antivm` — read-only VM detection.
- `was-evasion-sandbox` → `recon/sandbox` — read-only sandbox orchestrator.
- `was-evasion-timing` → `recon/timing` — read-only time-acceleration detection.
- `was-evasion-hwbp` → `recon/hwbp` — DR0-DR7 read-only inspection.
- `was-evasion-dllhijack` → `recon/dllhijack` — `Opportunity` discovery, never modifies.
- `was-system-drive` → `recon/drive` — drive enumeration.
- `was-system-folder` → `recon/folder` — special-folder path resolution.
- `was-system-network` → `recon/network` — interface IP enumeration.
- `was-system-lnk` → `persistence/lnk` — LNK creation, used by `persistence/startup`.
- `was-system-ads` → `cleanup/ads` — NTFS Alternate Data Stream data-hiding.
- `was-system-bsod` → `cleanup/bsod` — destructive system disruption.
- `was-system-ui` → `ui` (top-level) — interactive UX.
- `system/` directory **retired entirely**.

### Pass 2 — `runtime/` carve-out + `inject/` file split (later)

- `was-pe-clr` → `runtime/clr` — in-process .NET CLR host (executes
  managed code).
- `was-pe-bof` → `runtime/bof` — in-process COFF loader (executes BOF
  code).
- `inject/injector_windows.go` (one file) split into
  `injector_self_windows.go`, `injector_remote_windows.go`,
  `injector_hollow_windows.go` — no package rename, no API change.

### Pass 3 — `privesc/` + `credentials/` + `process/tamper/` + `persistence/account` (later)

- `was-uacbypass` → `privesc/uac` — UAC bypass methods.
- `was-exploit-cve202430088` → `privesc/cve202430088` — kernel LPE.
- `was-collection-lsassdump` → `credentials/lsassdump` — credential
  access ≠ collection.
- `was-evasion-hideprocess` → `process/tamper/hideprocess` — tampers
  remote process.
- `was-evasion-herpaderping` → `process/tamper/herpaderping` — process
  creation deception.
- `was-evasion-fakecmd` → `process/tamper/fakecmd` — own-PEB
  modification.
- `was-evasion-phant0m` → `process/tamper/phant0m` — kills threads in
  victim.
- `was-win-user` → `persistence/account` — local account management
  is persistence (T1136).

---

## 3 — Proposed final tree (post all 3 passes)

```
maldev/
│
│ # Layer 0 — pure Go (no OS calls)
├── crypto/                 — cipher primitives
├── encode/                 — text-safe payload transforms
├── hash/                   — MD/SHA + ROR13 + ssdeep + TLSH
├── random/                 — CSPRNG helpers
├── useragent/              — HTTP User-Agent database
│
│ # Layer 1 — OS primitives (truly low-level wrappers)
├── win/
│   ├── api/                — DLL handles, PEB walk, ROR13 export hashing
│   ├── syscall/            — Direct/Indirect syscall stubs + SSN resolvers
│   ├── ntapi/              — Typed Nt* wrappers
│   ├── token/              — Token theft + privilege adjust
│   ├── privilege/          — IsAdmin + LogonUser + RunAs
│   ├── impersonate/        — Thread impersonation
│   ├── version/            — RtlGetVersion + UBR
│   └── domain/             — NetGetJoinInformation
│
├── kernel/                 — BYOVD primitives
│   └── driver/
│       └── rtcore64/       — CVE-2019-16098
│
├── process/
│   ├── enum/               — cross-platform process listing
│   └── session/            — cross-session exec
│
│ # Layer 2 — passive recon (read-only)
├── recon/
│   ├── antidebug/          ← was-evasion-antidebug    [Pass 1 ✓]
│   ├── antivm/             ← was-evasion-antivm       [Pass 1 ✓]
│   ├── sandbox/            ← was-evasion-sandbox      [Pass 1 ✓]
│   ├── timing/             ← was-evasion-timing       [Pass 1 ✓]
│   ├── hwbp/               ← was-evasion-hwbp         [Pass 1 ✓]
│   ├── drive/              ← was-system-drive         [Pass 1 ✓]
│   ├── folder/             ← was-system-folder        [Pass 1 ✓]
│   ├── network/            ← was-system-network       [Pass 1 ✓]
│   └── dllhijack/          ← was-evasion-dllhijack    [Pass 1 ✓]
│
│ # Layer 2 — active evasion
├── evasion/
│   ├── amsi/               unchanged
│   ├── etw/                unchanged
│   ├── unhook/             unchanged
│   ├── sleepmask/          unchanged
│   ├── callstack/          unchanged
│   ├── kcallback/          unchanged
│   ├── acg/                unchanged
│   ├── blockdlls/          unchanged
│   ├── cet/                unchanged
│   ├── stealthopen/        unchanged (NTFS Object ID actively bypasses path hooks)
│   ├── hook/
│   │   ├── bridge/         unchanged
│   │   └── shellcode/      unchanged
│   └── preset/             unchanged
│
│ # Layer 2 — process state mutation [Pass 3]
├── process/tamper/
│   ├── hideprocess/        ← was-evasion-hideprocess
│   ├── herpaderping/       ← was-evasion-herpaderping
│   ├── fakecmd/            ← was-evasion-fakecmd
│   └── phant0m/            ← was-evasion-phant0m
│
│ # Layer 2 — code injection (file-split internally [Pass 2], package unchanged)
├── inject/
│
│ # Layer 2 — in-process code loaders [Pass 2]
├── runtime/
│   ├── clr/                ← was-pe-clr
│   └── bof/                ← was-pe-bof
│
│ # Layer 2 — PE binary manipulation
├── pe/
│   ├── parse/              unchanged
│   ├── strip/              unchanged
│   ├── morph/              unchanged
│   ├── imports/            unchanged
│   ├── cert/               unchanged
│   ├── srdi/               unchanged
│   ├── masquerade/         unchanged
│   └── winres/             unchanged
│
│ # Layer 2 — credential access [Pass 3]
├── credentials/
│   └── lsassdump/          ← was-collection-lsassdump
│
│ # Layer 2 — user-data collection
├── collection/
│   ├── keylog/             unchanged
│   ├── clipboard/          unchanged
│   └── screenshot/         unchanged
│
│ # Layer 2 — persistence
├── persistence/
│   ├── registry/           unchanged
│   ├── startup/            unchanged
│   ├── scheduler/          unchanged
│   ├── service/            unchanged
│   ├── lnk/                ← was-system-lnk         [Pass 1 ✓]
│   └── account/            ← was-win-user           [Pass 3]
│
│ # Layer 2 — privilege escalation [Pass 3]
├── privesc/
│   ├── uac/                ← was-uacbypass
│   └── cve202430088/       ← was-exploit-cve202430088
│
│ # Layer 2 — post-ex hygiene + anti-forensic
├── cleanup/
│   ├── selfdelete/         unchanged
│   ├── memory/             unchanged
│   ├── service/            unchanged
│   ├── timestomp/          unchanged
│   ├── wipe/               unchanged
│   ├── ads/                ← was-system-ads         [Pass 1 ✓]
│   └── bsod/               ← was-system-bsod        [Pass 1 ✓]
│
│ # Layer 2 — interactive UI
├── ui/                      ← was-system-ui          [Pass 1 ✓]
│
│ # Layer 3 — orchestration
├── c2/
│   ├── shell/              unchanged
│   ├── transport/
│   │   └── namedpipe/      unchanged
│   ├── multicat/           unchanged
│   ├── meterpreter/        unchanged
│   └── cert/               unchanged
│
├── cmd/                    unchanged
├── internal/               unchanged
├── testutil/               unchanged
└── docs/                   unchanged
```

**Top-level dir count:** 16 post-Pass-1 (was 18 with `system/` 7-deep
+ `exploit/` + `uacbypass/` flat). After Pass 3 it stays at 16 (one
out — `exploit/` and `uacbypass/` retire; one in — `privesc/` and
`credentials/`).

---

## 4 — Migration plan (3 versioned passes)

### Pass 1 — `recon/` carve-out + `system/` retirement (v0.20.0) — IN FLIGHT

13 directory renames, ~80 import-path rewrites. Closes Themes A
(recon misfit) and B (system junk drawer).

### Pass 2 — `runtime/` carve-out + `inject/` file split (v0.21.0)

Closes Themes C (pe/ vs runtime/) and G (inject/ visibility). 2
directory renames + 3 file splits. No API change.

### Pass 3 — `privesc/` + `credentials/` + `process/tamper/` + `persistence/account` (v0.22.0)

Closes Themes D, E, F, and the rest of A. ~9 directory renames
(uacbypass, exploit/cve202430088, collection/lsassdump, win/user,
hideprocess, herpaderping, fakecmd, phant0m).

### Why three passes (not one)

Each pass is a **single coherent theme** — easier to review, easier
to revert if it surfaces problems. Tag-bumping per pass gives external
consumers a clear migration story (changelog per pass). Reduces
merge-conflict risk.

---

## 5 — Decisions locked for Pass 1

1. Top-level name: **`recon/`** (matches MITRE Discovery tactic).
2. `system/` retires entirely; **`ui/`** moves to top-level.
3. Package names **unchanged** (only paths move). `antidebug` and
   `antivm` keep the well-known `anti-` prefix as terms of the art.
4. **No type aliases** — clean break, bump tag. Published-module
   external consumers update their imports.
5. **`inject/` stays one Go package** — Pass 2 will split files
   internally, not sub-package.

---

## 6 — What does NOT change

- All Layer-0 packages stay put.
- All `win/*` packages stay (except `win/user` which moves to
  `persistence/account` in Pass 3).
- The `evasion.Technique` interface, `evasion.ApplyAll` orchestrator,
  and the `inject.Injector` + `Pipeline` interfaces — all unchanged.
- `c2/*` is untouched.
- `cleanup/*`, `persistence/*`, `collection/*`, `pe/*` keep their
  semantics; only the misfits move IN or OUT.
- `kernel/driver*` (just shipped this session) stays put.
- All `evasion.Caller` patterns, all `wsyscall` plumbing, all
  evasion-presets.
