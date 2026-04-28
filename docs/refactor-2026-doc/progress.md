---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

# Documentation refactor — progress tracker

> **Read this file first** when picking the refactor up on another
> machine or after a session break. It is the canonical view of what's
> done, what's in flight, and what comes next.

## Source of truth

- **Methodology**: [`docs/conventions/documentation.md`](../conventions/documentation.md)
  — templates, voice, GFM features, migration order. Do not write any
  documentation without consulting this skill first.
- **Pre-refactor audit**: [`audit-2026-04-27.md`](audit-2026-04-27.md)
  — exhaustive inventory of 180 packages, MITRE typos, stale links,
  missing technique pages. The "concrete cleanup task list" at the
  end of that file is the master TODO list.
- **Auto-generation**: `cmd/docgen` regenerates the autogen blocks in
  `docs/index.md` (and `docs/mitre.md` once markers are added there)
  from each package's `doc.go`. Run `go run ./cmd/docgen` after editing
  any `doc.go`.

## Phase status

| Phase | Status | Commit | Scope |
|---|---|---|---|
| 1 — README + index + 3 role pages | ✅ done | `07ced18` | Replaces dense Technique Reference table with role-based entry points (operator / researcher / detection-eng) and a navigation spine in `docs/index.md`. |
| 2 — `cleanup/*` demonstrator area | ✅ done | `11838e3` | All 7 packages refactored to template (doc.go + tech md + example_test.go). 4 NEW tech pages: ads, bsod, service, wipe. |
| 3 — `cmd/docgen` + pre-commit + CI drift check | ✅ done | `b2e0464` | Drift check wired into `scripts/pre-commit` and `.github/workflows/docs.yml`. README package map fix in `0587c76`. |
| 4 — sweep remaining 10 areas | ✅ done | `57c853b..` | All areas swept (cleanup, evasion, inject, layer-0, c2, collection, credentials, pe, persistence, process, recon, runtime, win, kernel, privesc, ui). Polish round for evasion legacy md pages deferred to Phase 6. |
| 5 — transversal guides | 🟡 in-progress | — | mitre.md updated (T1016, T1027.007, T1068, T1078, T1134.001/002/004 enrichment). getting-started.md detection scale aligned to canonical 5-level. architecture.md per-package quick-reference fixed (kernel/driver/rtcore64 row, privesc → new tech md links, persistence/service+lnk+account rows added). testing.md, coverage-workflow.md still need a pass. |
| 6 — final cross-link + breadcrumb + dead-link audit | ✅ done | `d1ff2d7..a705c32, 6b` | Repo-wide dead-link sweep (8 broken refs fixed) + repo-wide front-matter pass: 45 `docs/**.md` pages now carry `last_reviewed: 2026-04-27 / reflects_commit: a705c32`. Every `docs/` page now has uniform front-matter — index entries, by-role pages, area docs, transversal guides, technique md, examples. |
| 3b — gh-pages mdBook deploy | ✅ done | `40cdcd9` | Live at <https://oioio-space.github.io/maldev/>. `book.toml` + `docs/SUMMARY.md` (176 entries) + `.github/workflows/mdbook.yml`. CI installs mdBook 0.4.40 + mdbook-mermaid 0.14.0 on push to `master`, strips YAML front-matter from copied md, rewrites `../README.md` → absolute GitHub URL, deploys to GitHub Pages via `actions/deploy-pages@v4`. Pages enabled with `gh api -X POST repos/.../pages -f build_type=workflow`. First successful deploy: workflow run 25037092496, build 12s + deploy 11s. |

## Phase 4 progress

Order (per Phase 1 user direction): **evasion → inject → crypto+encode+hash → c2 → collection → credentials → pe → persistence → process → recon → runtime → win**.

Each area gets:

- 1 area `README.md` rewrite (under `docs/techniques/<area>/`) — index, decision tree, MITRE table.
- One `doc.go` rewrite per package (template: package-doc + `# MITRE ATT&CK` + `# Detection level` + `# Example` ref + `# See also`).
- One `<pkg>_example_test.go` per package (Simple / Composed / Advanced / Complex tiers).
- One per-package tech `.md` (template: TL;DR / Primer / How It Works / API Reference / Examples / OPSEC & Detection / MITRE ATT&CK / Limitations / See also).

### Per-area status

| Area | doc.go | tech md | example_test.go | Notes |
|---|---|---|---|---|
| `cleanup/*` | ✅ 7/7 | ✅ 7/7 + README | ✅ 8/8 | Done in Phase 2 (`11838e3`). Reference shape for everything below. |
| `evasion/*` | ✅ 12/12 | 🟡 4/~10 | ✅ 12/12 | **Mostly done.** All doc.go aligned to template; every package has example_test.go covering the exported API. Tech-md template rewrites done for amsi-bypass, etw-patching, sleep-mask (rewritten in 4b? — check), cet (NEW). Tech-md still legacy on: acg-blockdlls, callstack-spoof, inline-hook, kernel-callback-removal, ntdll-unhooking, preset, sleep-mask, stealthopen — do them in a polish round if time, low priority since legacy content is reasonable. **Cross-categorised pages** still living under evasion/ but documenting non-evasion packages: anti-analysis (recon), byovd-rtcore64 (kernel/driver), dll-hijack (recon), fakecmd/hideprocess/phant0m (process/tamper), hw-breakpoints (recon), ppid-spoofing (c2/shell), sandbox/timing (recon) — to be reorganised in Phase 6. |
| `inject` | ✅ 1/1 | ✅ 12/12 | ✅ 1/1 | Done (sweep landed in commits `4798780..ab0f7f8`). doc.go aligned to template; `inject_example_windows_test.go` added (5 godoc examples covering DefaultWindowsConfig / Build / Pipeline / chained / InjectWithFallback). All 12 tech pages rewritten to template (Group A: CRT, EarlyBird, ThreadHijack — Group B: Callback, ThreadPool, ModuleStomp, SectionMap — Group C: KCT, PhantomDLL, EtwpCreateEtwThread — Group D: NtQueueApcThreadEx, ProcessArgSpoofing) plus area README refreshed (decision flow, SelfInjector contract, syscall modes, MITRE table). |
| `crypto / encode / hash` | ✅ 5/5 | ✅ 5/5 | ✅ 5/5 | Layer 0 done. doc.go + example_test.go landed earlier (`cf. f815d85`); tech md split into three areas this session: `docs/techniques/crypto/{README,payload-encryption}.md`, `docs/techniques/encode/{README,encode}.md`, `docs/techniques/hash/{README,cryptographic-hashes,fuzzy-hashing}.md` (fuzzy moved out of crypto/). Counts include `random` + `useragent` (Layer 0 helpers, doc.go + example_test.go templated; no dedicated tech md — both are utilities surfaced in their consumers' pages). |
| `c2/*` | ✅ 7/7 | ✅ 7/7 | ✅ 7/7 | Sweep landed in commits `36484a4..` (this session). All 7 doc.go aligned to template; example_test.go inherited from earlier work; tech md (`README.md`, `reverse-shell.md`, `transport.md`, `meterpreter.md`, `multicat.md`, `namedpipe.md`, `malleable-profiles.md`) rewritten with full API Reference + 4-tier examples + OPSEC table + MITRE rollup. |
| `collection/*` | ✅ 3/3 | ✅ 3/3 + README | ✅ 3/3 | Done. All 3 doc.go aligned to template; README + 3 tech pages (keylogging, clipboard, screenshot) rewritten to template. `alternate-data-streams.md` + `lsass-dump.md` stay here as cross-ref stubs with a NOTE pointing to canonical owners; will move in Phase 6. |
| `credentials/*` | ✅ 4/4 | ✅ 4/4 + README | ✅ 4/4 | Done (commits `cfd7730..`). doc.go aligned to template (goldenticket, lsassdump, samdump, sekurlsa). 3 NEW tech pages (goldenticket, lsassdump, samdump) + area README rewrite (Mermaid flow, decision tree, MITRE table with D3FEND counters, Pass-the-X chains documented end-to-end). `sekurlsa.md` carries the older heading order (Primer / How It Works / Simple Example / Composed / Advanced / Limitations / API Reference) — left intact for now, re-aligned in Phase 6. example_test.go sizes match c2 baseline. |
| `pe/*` | ✅ 8/8 | ✅ 6/6 + README | ✅ 7/7 | Done. doc.go aligned to template (pe umbrella + cert, imports, masquerade, morph, parse, srdi, strip). Stale references to pe/bof + pe/clr removed (now under runtime/). 7 example_test.go (one per sub-package). 6 tech md fully rewritten to canonical template (TL;DR / Primer / How It Works / API Reference / Examples / OPSEC & Detection / MITRE ATT&CK / Limitations / See also): certificate-theft, imports, masquerade, morph, pe-to-shellcode, strip-sanitize. README rewrite: Mermaid offline→runtime flow, 6-step layered scrub recipe, MITRE+D3FEND table. pe/parse covered by README + doc.go (no dedicated tech md — pure helper for other pe/* packages). |
| `persistence/*` | ✅ 7/7 | ✅ 6/6 + README | ✅ 6/6 | Done. doc.go aligned + 6 tech md (3 NEW: account, lnk, service · 3 rewrites: registry, startup-folder, task-scheduler) + README rewrite (Mermaid trigger→mech→compose flow + redundancy recipe + MITRE+D3FEND). Note: `persistence/account/` directory declares `package user` (Win32 API surface name). |
| `process/*` | ✅ 7/7 | ✅ 6/6 + README | ✅ 6/6 | Done. doc.go aligned + 6 tech md (3 NEW: enum, session, herpaderping · 3 moved+rewritten from evasion/: fakecmd, hideprocess, phant0m) + new README under fresh `docs/techniques/process/` directory. evasion/README cross-refs updated to point at `../process/<name>.md`. evasion area's "cross-categorised" table now correctly delegates these 3 pages to their owner directory. |
| `recon/*` | ✅ 9/9 | ✅ 8/8 + README | ✅ 9/9 | Done (commits f31fca1..ad40545). doc.go aligned + 9 NEW example_test.go + 8 tech md (5 ports from evasion/: anti-analysis, dll-hijack, hw-breakpoints, sandbox, timing · 3 NEW: drive, folder, network) + new README under docs/techniques/recon/. evasion/README cross-categorised table updated. |
| `runtime/*` | ✅ 2/2 | ✅ 2/2 | ✅ 2/2 | Done (`11543a1`). bof + clr aligned to template, full Mermaid + API Reference. |
| `win/*` | ✅ 8/8 | 🟡 4/8 | ✅ 8/8 | doc.go + example_test.go landed for all 8. Tech md: api/syscall/ntapi covered by `docs/techniques/syscalls/*`; token/impersonate/privilege covered by `docs/techniques/tokens/*`. **Missing**: dedicated pages for domain + version (host fingerprinting). |
| `kernel/driver/*` | ✅ 2/2 | ✅ 1/1 + README | ✅ 2/2 | Done. doc.go aligned for both `kernel/driver` umbrella + `rtcore64` sub-package. New `docs/techniques/kernel/README.md` + `byovd-rtcore64.md` moved from `docs/techniques/evasion/` (front-matter + breadcrumb fixed). evasion/README cross-categorised table updated to delegate. Existing rtcore64_example_test.go retained. |
| `privesc/*` | ✅ 2/2 | ✅ 2/2 + README | ✅ 2/2 | Done. doc.go aligned for cve202430088 + uac. New `docs/techniques/privesc/{README,uac,cve202430088}.md` with full Mermaid + API Reference + 4-tier examples + OPSEC table + MITRE rollup. uac.md documents all 5 entry points (FODHelper / SLUI / SilentCleanup / EventVwr / EventVwrLogon) with build-window tables. cve202430088.md includes BSOD-risk warnings + chain-fall-through example. Existing example_test.go files retained. |
| `ui` | ✅ 1/1 | n/a | ✅ 1/1 | doc.go already templated upstream. example_test.go present. No dedicated tech md — utility surface only. |
| `useragent`, `random` | ✅ 2/2 | n/a | ✅ 2/2 | Folded into Layer 0 row above. `random/doc.go` + `useragent/doc.go` templated; example_test.go present. |

## Resuming after a break

If you are picking this up on another machine:

1. `git pull` to land at the latest tip.
2. Read this file (`docs/refactor-2026-doc/progress.md`) — the table
   above shows exactly where the previous session stopped.
3. Read [`docs/conventions/documentation.md`](../conventions/documentation.md)
   — the templates and rules.
4. Read [`audit-2026-04-27.md`](audit-2026-04-27.md) — for context on
   why the refactor exists at all and the master TODO list.
5. Continue from the "🟡 in-flight" cell in the table above.

If `cmd/docgen --check` exits non-zero, run `go run ./cmd/docgen` and
commit the resulting markdown change before doing anything else — the
autogen tables must always reflect the current state of all `doc.go`
files.

## Update protocol

Every commit that completes part of a phase MUST also update this file:

- Tick the relevant cell in the per-area status table.
- Bump the front-matter `last_reviewed` and `reflects_commit`.
- If a phase fully completes, change the row in "Phase status" from
  🟡 to ✅ and record the commit SHA.

Treat this file as load-bearing infrastructure — same as
`doc-conventions.md`. If you skip an update here, future-you (or a
collaborator on a different machine) is stranded.
