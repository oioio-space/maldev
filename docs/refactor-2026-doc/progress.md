---
last_reviewed: 2026-04-27
reflects_commit: ab0f7f8
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
| 4 — sweep remaining 10 areas | 🟡 in-progress | — | See "Phase 4 progress" below. |
| 5 — transversal guides | ⬜ pending | — | architecture.md, getting-started.md, mitre.md (regen), testing.md, coverage-workflow.md. |
| 6 — final cross-link + breadcrumb + dead-link audit | ⬜ pending | — | Repo-wide pass. Includes `last_reviewed` bump on every page. |
| 3b — gh-pages mdBook deploy | ⬜ deferred | — | After Phase 6 stabilises, add the gh-pages workflow that builds an mdBook from `docs/`. |

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
| `c2/*` | ⬜ 0/7 | ⬜ 0/6 | ⬜ 0/7 | Includes `c2/transport/namedpipe`. |
| `collection/*` | ⬜ 0/3 | ⬜ 0/5 | ⬜ 0/3 | Existing pages cover keylog, clipboard, screenshot, alternate-data-streams, lsass-dump. The last two are mis-categorised — decide canonical home in Phase 6. |
| `credentials/*` | ⬜ 0/4 | ⬜ 0/3 | ⬜ 0/4 | Big content — sekurlsa is 109-line doc.go already. Audit flagged 3 missing pages: goldenticket, samdump, plus the existing sekurlsa. |
| `pe/*` | ⬜ 0/7 | ⬜ 0/7 | ⬜ 0/7 | Existing pages: certificate-theft, imports, masquerade, morph, pe-to-shellcode, strip-sanitize. |
| `persistence/*` | ⬜ 0/6 | ⬜ 0/3 | ⬜ 0/6 | Audit flagged 3 missing tech pages: account, lnk, service. |
| `process/*` | ⬜ 0/6 | ⬜ 0/3 | ⬜ 0/6 | Includes `process/tamper/*`. Audit flagged: herpaderping (no .md despite 112-line doc.go!), enum, session. |
| `recon/*` | ⬜ 0/9 | ⬜ 0/8 | ⬜ 0/9 | Existing pages partly under `docs/techniques/evasion/` (anti-analysis, dll-hijack, hw-breakpoints, sandbox, timing) — re-locate in Phase 6 or accept the categorisation. |
| `runtime/*` | ⬜ 0/2 | ⬜ 0/2 | ⬜ 0/2 | bof, clr — both have existing tech pages. |
| `win/*` | ⬜ 0/8 | ⬜ 0/3 | ⬜ 0/8 | win/syscall + win/ntapi + win/api covered by `docs/techniques/syscalls/*`. The other 5 (domain, impersonate, privilege, token, version) lack per-package pages. |
| `kernel/driver/*` | ⬜ 0/2 | ⬜ 0/1 | ⬜ 0/2 | Single tech page (byovd-rtcore64.md) currently under `docs/techniques/evasion/`. |
| `privesc/*` | ⬜ 0/2 | ⬜ 0/1 | ⬜ 0/2 | Audit flagged 1 missing page (cve202430088). uac is folded into docs/privilege.md only. |
| `ui` | ⬜ 0/1 | ⬜ 0/0 | ⬜ 0/1 | Tiny — MessageBoxW + sounds. No tech page yet. |
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
