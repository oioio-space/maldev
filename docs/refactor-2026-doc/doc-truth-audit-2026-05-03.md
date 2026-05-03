---
last_reviewed: 2026-05-03
purpose: Doc-vs-code truth audit with E2E (user + admin) coverage on Windows VMs
distinct_from: refactor-2026-doc/progress.md (structural refactor) and backlog-2026-04-29.md (mdBook polish)
---

# Doc-truth audit + E2E coverage — 2026-05-03

The audit triggered by user feedback on 2026-05-03 :
> *« j'ai essayé d'implémenter le dllhijacking à partir de la doc et rien n'est bon […] mets à jour la doc partout, fais des programmes d'exemple combinant plusieurs techniques. »*

The strategy : build **panorama programs** (each combining 3-6 techniques per the docs) under `cmd/examples/<scenario>/`, run them on win10 + win11-2 in **both `lowuser` (non-admin)** and **`test` (admin)** modes via `vmtest -bin -matrix`, and (a) fix the docs that diverge from the real API, (b) fix the code where the divergence is "doc-promised feature missing", (c) capture the admin/user behaviour delta as the canonical reference for "what works without admin".

## Tooling state

- `cmd/vmtest/runbin.go` — `-bin` mode, drives cross-build + push + run.
- `scripts/vm-test/provision-lowuser.ps1` — idempotent low-priv user setup (Users group, SeBatchLogonRight, scratch dir at `C:\Users\Public\maldev`).
- `scripts/vm-test/run-as-lowuser.ps1` — Task-Scheduler launch + `Get-ScheduledTaskInfo.LastTaskResult` poll, surfaces `###RC=<n>` sentinel.
- Memory: `~/.claude/projects/.../memory/vmtest_lowuser_runner.md` (gotchas list, do not re-debug).

## Panorama backlog

Each panorama lives at `cmd/examples/<id>/main.go` + a walkthrough at `docs/examples/<id>.md`. The matrix is win10 / win11-2 × admin / lowuser = 4 cells. A row is **green** when all 4 cells produce the expected output (success or controlled "Accès refusé" — both are valid data).

| # | Panorama | Combines | Status | Notes |
|---|---|---|---|---|
| 1 | `stealth-recon-ppid` | win/syscall (Tartarus + IndirectAsm) + evasion/stealthopen + evasion/preset + recon/dllhijack + c2/shell PPID | ✅ matrix run | Done 2026-05-03. See observations below. Open fixes : doc-drift Opportunity fields, clarify-doc admin caveats. |
| 2 | `injection-evasion` | wsyscall (Tartarus + Indirect) + evasion/preset.Stealth + inject.ThreadPoolExec + evasion/sleepmask + cleanup/memory.SecureZero | ✅ matrix green | Done 2026-05-03. All 4 cells rc=0. Doc clarification queued (SecureZero target). |
| 3 | `unhook-suite` | evasion/unhook (Classic + Full) + evasion/ntdll-unhooking + win/syscall callers | ⏳ pending | Per-method unhook coverage. |
| 4 | `recon-suite` | recon/{anti-analysis,sandbox,timing,network,drive,folder,hw-breakpoints} | ⏳ pending | All sandbox/AV checks. |
| 5 | `persistence-user` | persistence/{registry,startup,scheduler} (HKCU paths) | ⏳ pending | Survives without admin? |
| 6 | `persistence-admin` | persistence/{service,account,task-scheduler-SYSTEM,lnk} | ⏳ pending | Admin-only persistence. |
| 7 | `tokens-impersonation` | tokens/{impersonation,token-theft,privilege-escalation} | ⏳ pending | Token games. |
| 8 | `privesc-uac` | privesc/{uac,cve202430088} + recon/dllhijack autoElevate | ⏳ pending | UAC bypass. |
| 9 | `credentials` | credentials/{lsassdump,samdump,sekurlsa,goldenticket} | ⏳ pending | Cred extraction. |
| 10 | `cleanup-suite` | cleanup/{ads,timestomp,self-delete,memory-wipe,wipe} | ⏳ pending | Anti-forensics. |
| 11 | `pe-suite` | pe/{cert,dll-proxy,masquerade,morph,imports,pe-to-shellcode,strip-sanitize} | ⏳ pending | PE manipulation. |
| 12 | `process-tamper` | process/{fakecmd,herpaderping,hideprocess,phant0m} | ⏳ pending | Process evasion. |
| 13 | `collection-suite` | collection/{clipboard,screenshot,keylogging,lsass-dump,alternate-data-streams} | ⏳ pending | Data collection. |
| 14 | `runtime-loaders` | runtime/{bof-loader,clr} + injection/{phantom-dll,module-stomping,section-mapping} | ⏳ pending | Loader variants. |
| 15 | `c2-suite` | c2/{transport,reverse-shell,namedpipe,multicat,malleable-profiles} | ⏳ pending | C2 plumbing. |
| 16 | `kernel-byovd` | kernel/byovd-rtcore64 + (admin only) | ⏳ pending | BYOVD admin-only. |

Layer-0 docs (`crypto/`, `encode/`, `hash/`, `random/`, `useragent/`) and most of `win/{api,ntapi,token,privilege,version,domain,impersonate}` are *primitives* with no admin/user delta worth E2E-testing — they are exercised transitively by every panorama and audited statically by the per-package code review.

## Doc-vs-code findings (running log)

Add a row whenever a panorama or audit reveals a mismatch. Decision column: **fix-doc** (doc is wrong, code is the truth) | **fix-code** (doc promises a coherent feature the code lacks) | **clarify-doc** (doc is technically correct but missed an admin-only constraint that surfaces in the user-mode matrix).

| Doc | Symbol / claim | Reality | Decision | Status |
|---|---|---|---|---|
| `docs/techniques/recon/dll-hijack.md:80` | `Opportunity.Binary` | not in struct | fix-doc | TODO |
| `docs/techniques/recon/dll-hijack.md:80` | `Opportunity.MissingDLL` | not in struct | fix-doc | TODO |
| `recon/dllhijack/scan_services_windows.go:28-35` | `ScanServices` aborts on SCM connect failure | per audit, individual scanners abort but `ScanAll` partial-fails. Doc silent. | clarify-doc + fix-code | TODO — `ScanServices` standalone should return `(opps,err)` with the err wrapped, never panic on per-system errors |
| `recon/dllhijack/scan_processes_windows.go:31-32` | `ScanProcesses` aborts on `enum.List()` error | same pattern | clarify-doc + fix-code | TODO |
| `recon/dllhijack/scan_autoelevate_windows.go:32-38` | `ScanAutoElevate` aborts on System32 read failure | same pattern | clarify-doc + fix-code | TODO |
| `docs/techniques/evasion/stealthopen.md` | `NewStealth(path)` returns `(*Stealth, error)` | works **but** silently requires admin to obtain Object ID on system files (matrix evidence: `obtain ObjectID: Accès refusé` for lowuser on `C:\Windows\System32\ntdll.dll`) | clarify-doc | TODO — add an "Admin needed for Object ID stamping on system files" note to the Limitations block |
| `docs/techniques/evasion/ppid-spoofing.md` | "legitimate Windows API feature, Go 1.24+ native support" | admin SSH session can `OpenProcess(explorer)` and build SysProcAttr, **but** `cmd.Output()` → `CreateProcess` fails with `Accès refusé` even as admin on both Win10 and Win11 (likely integrity-level mismatch: SSH-launched admin = High IL, explorer = Medium IL) | clarify-doc | TODO — add an "integrity-level constraint" note. Spawning a child of an interactive-session process from a non-interactive admin session is denied. Test must run from an interactive shell (or pick a non-interactive parent like svchost). |
| `docs/techniques/evasion/sleep-mask.md` + `docs/techniques/cleanup/memory-wipe.md` | "Real beacon loop" example sets the region to RX then leaves it; thread-pool.md "Complex" example wipes via `memory.SecureZero(shellcode)` | the `shellcode []byte` heap slice is what gets zeroed; the RX page is read-only and SecureZero on it crashes with access violation. Easy mistake when conflating the two examples. | clarify-doc | TODO — add a "wipe target = the heap-side plaintext, not the RX page" note to memory-wipe.md, or mention it in sleep-mask.md "Common Pitfalls". |

## E2E observations from completed panoramas

### Panorama 1 — `stealth-recon-ppid` (matrix run, 2026-05-03)

Legend : ✅ success, ⚠️ partial / non-fatal degradation, ❌ failed (with reason).

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `wsyscall.New(MethodIndirectAsm, NewTartarus())` | ✅ | ✅ | ✅ | ✅ | OK |
| `stealthopen.NewStealth(ntdll)` | ✅ | ❌ Object ID stamping denied | ✅ | ❌ same | clarify-doc — admin needed on system files |
| `unhook.FullUnhook(caller, stealth)` | ✅ | ❌ nil opener (downstream) | ✅ | ❌ same | OK once stealth is captured |
| `evasion.ApplyAll(preset.Stealth(), caller)` | ✅ | n/a (skipped) | ✅ | n/a | OK |
| `dllhijack.ScanAll()` services | ✅ found 5 Edge Elevation candidates (CRYPT32, WTSAPI32, dbghelp, ncrypt, ntdll) | ⚠️ services scanner SCM-denied, processes scanner OK | ✅ same Edge candidates | ⚠️ same | clarify-doc — services scanner needs admin; partial errors are reported but `ScanAll` keeps going |
| `dllhijack.ScanAll()` processes | ✅ | ✅ but only sees own process | ✅ | ✅ same | OK — Toolhelp32 is per-session |
| `shell.NewPPIDSpoofer().FindTargetProcess()` | ✅ explorer at PID 4836/6416 | ✅ same | ✅ | ✅ | OK |
| `shell.SysProcAttr()` → `OpenProcess(parent)` | ✅ | ❌ Accès refusé | ✅ | ❌ same | clarify-doc — lowuser cannot open parent owned by admin user |
| `cmd.Output()` (PPID-spoofed CreateProcess) | ❌ `fork/exec cmd.exe: Accès refusé` even as admin | n/a | ❌ same | n/a | **NEW finding** — admin SSH session (non-interactive) cannot spawn child of interactive-session explorer ; integrity-level mismatch. The doc claims it "just works" but the example needs a non-interactive parent (svchost) or to run from an interactive console. |

Decisions captured in the doc-drift table above.

### Panorama 2 — `injection-evasion` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `wsyscall.New(MethodIndirect, NewTartarus())` | ✅ | ✅ | ✅ | ✅ | OK |
| `evasion.ApplyAll(preset.Stealth(), caller)` | ✅ "applied cleanly" | ✅ same | ✅ | ✅ | OK — AMSI + ETW + 10x Classic unhook all succeed for an unprivileged caller |
| `inject.ThreadPoolExec(shellcode)` | ✅ "dispatched + ret returned" | ✅ same | ✅ | ✅ | OK — TpAllocWork/TpPostWork/TpWaitForWork on the local pool needs no admin |
| `sleepmask.New(...).Sleep(ctx, 1.5s)` (XOR + InlineStrategy) | ✅ region restored to RX | ✅ same | ✅ | ✅ | OK |
| `cleanup/memory.SecureZero(plaintext)` | ✅ | ✅ | ✅ | ✅ | OK once we zero the heap slice (initial draft tried to zero the RX page → access violation; doc would benefit from clarifying the wipe target) |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | full panorama green |

Validates the canonical "init beacon" sequence end-to-end. Notable that **none of these steps require admin**: a non-admin local user can silence AMSI/ETW in their own process, dispatch shellcode on the existing thread pool, and mask the region — exactly the threat model EDRs need to defend against.

## Workflow per panorama

1. Pick the next ⏳ row in the backlog.
2. Read **only** the matching `docs/techniques/<area>/<file>.md` files (no source-code lookup) — this is the user's reproduction protocol.
3. Write `cmd/examples/<id>/main.go` and `docs/examples/<id>.md` from the docs.
4. `GOOS=windows go build ./cmd/examples/<id>/` — list every build error, mark as DOC-DRIFT in the running log above, decide fix-doc vs fix-code, patch the smallest set that compiles.
5. `vmtest -bin=cmd/examples/<id> -matrix windows windows11` (matrix flag added to runbin.go in this batch) — run admin + lowuser on both VMs.
6. Capture the matrix in this doc under "E2E observations".
7. Apply the doc/code fixes from steps 4 + 6. `/simplify` + skill check before commit.
8. Commit with a `panorama(<id>)` scope. Tick the row to ✅.
