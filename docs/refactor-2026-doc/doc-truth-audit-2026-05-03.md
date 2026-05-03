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
| 3 | `unhook-suite` | evasion/unhook ClassicUnhook + FullUnhook + PerunUnhook + IsHooked × 3 caller backends (WinAPI nil / Indirect+Tartarus / IndirectAsm+HashGate) | ✅ matrix green | Done 2026-05-03. All variants OK on all 4 cells. Doc API matches code, no drift. |
| 4 | `recon-suite` | recon/{anti-analysis,sandbox,timing,network,drive,folder,hw-breakpoints} | ✅ matrix green | Done 2026-05-03. All 4 cells rc=0. Findings: drive.New needs trailing `\`; hwbp.Breakpoint missing Module+TID fields. |
| 5 | `persistence-user` | persistence/{registry,startup,scheduler} (HKCU paths) | ✅ matrix run | Done 2026-05-03. **Major findings**: HKCU Run OK for both. Startup folder fails for lowuser (no interactive profile = no Shell folders). Scheduler at root path `\<name>` requires admin even with WithTriggerLogon. |
| 6 | `persistence-admin` | persistence/{account,service,lnk} | ✅ matrix run | Done 2026-05-03. Clean 3-for-3 admin success / 3-for-3 lowuser denial — the doc-truth-audit's clearest differential row. Doc-drift: persistence/account is `package user`, doc relies on implicit alias. |
| 7 | `tokens-impersonation` | impersonate.ThreadEffectiveTokenOwner + privilege.IsAdmin / IsAdminGroupMember + token.StealByName(winlogon, explorer) + IntegrityLevel | ✅ matrix run | Done 2026-05-03. Clean differential: admin steals winlogon SYSTEM token + explorer Medium token, lowuser gets `open process: Accès refusé` for both. Identity probes work everywhere. |
| 8 | `privesc-uac` | privesc/uac (FODHelper/SilentCleanup/EventVwr/SLUI) + win/version pre-flight + privilege.IsAdmin gating | ✅ matrix run | Done 2026-05-03. API surface verified, gating works. **Limitation surfaced**: SSH-launched admin = High-IL Elevated, lowuser = no admin group at all — neither cell hits the "Medium-IL admin" scenario UAC bypasses target. To actually exercise FODHelper would require an interactive RDP/console admin session. Doc's "Composed" pre-flight correctly handles both early-out cases. |
| 9 | `credentials-suite` | credentials/{lsassdump.DumpToFile, samdump.LiveDump, goldenticket.Forge} | ⚠️ matrix run, findings | Done 2026-05-03. Goldenticket forge works everywhere. lsass dump differential interesting (Win10 admin OK, Win11 admin ErrOpenDenied — likely Win11 RunAsPPL default, sentinel routing imprecise). LiveDump fails on all 4 cells — needs investigation. **Doc-drifts:** `goldenticket.Hash{Type, Bytes}` (doc says `EType`); `ETypeAES256CTS` (doc says `ETypeAES256CTSHMACSHA196`). |
| 10 | `cleanup-suite` | cleanup/{ads,timestomp,memory-wipe} (skips selfdelete to avoid terminating the runner) | ✅ matrix green | Done 2026-05-03. All 4 cells rc=0. Doc-drift: `ads.List` returns structs with name+size, doc shows `[]string`. |
| 11 | `pe-suite` | pe/{imports.List, cert.Has+Read, strip.Sanitize, srdi.ConvertFile} | ✅ matrix green | Done 2026-05-03. All 4 cells rc=0 with full parity admin/lowuser. **Doc-clarif**: notepad.exe is catalog-signed, not Authenticode-embedded; `cert.Copy(notepad.exe, …)` in the doc would fail — pick a different sample. |
| 12 | `process-tamper` | process/enum.List + process/session.Active + process/tamper/fakecmd.Spoof+Restore | ✅ matrix run | Done 2026-05-03. enum/fakecmd parity admin/lowuser. session.Active inconsistent for lowuser (likely returns empty / errors when invoked from session 0 task). **Doc-drift**: session.Info real fields are `ID/Name/State/User/Domain`, doc says `SessionID/Username`. |
| 13 | `collection-suite` | collection/{clipboard.ReadText, screenshot.Capture, keylog.Start} | ✅ matrix run | Done 2026-05-03. lsass-dump + ADS already covered by panoramas 9 + 10. **Session-0 limitation surfaced**: every collection primitive is interactive-session-bound; SSH admin + scheduled-task lowuser both run in session 0 → empty clipboard, screen-capture-failed, keylogger receives no events. The doc could call this out: "collection requires running inside a user logon session (interactive desktop), not via service / scheduled task / SSH". |
| 14 | `runtime-loaders` | runtime/{bof.Load, clr.Load+ExecuteAssembly} + inject.ModuleStomp | ✅ matrix run | Done 2026-05-03. bof + ModuleStomp parity admin/lowuser. clr fails identically on all 4 cells with the doc-aligned "install .NET 3.5" message — known TOOLS-snapshot blocker (memory `clr_v2_activation_blocker`). |
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
| `docs/techniques/recon/drive.md:Simple` | `drive.New("C:")` | rejects `"C:"`, requires `"C:\"` (Win10 + Win11 both fail with `syntax incorrect`) | fix-doc | TODO — change the example to use a raw string `\`C:\\\``. |
| `docs/techniques/recon/hw-breakpoints.md:Simple` | `bp.Module`, `bp.TID` | neither field exists on `hwbp.Breakpoint` | fix-doc | TODO — list the real fields (run a quick godoc check first). |
| `docs/techniques/persistence/startup-folder.md` | `startup.Install("name", path, args)` | works for users with an existing interactive profile; on accounts that have never logged in interactively, `SHGetKnownFolderPath` for the Startup CSIDL returns "file not found" because the per-user Shell folders aren't registered yet | clarify-doc | TODO — add a "Requires the user account to have logged in at least once interactively (the Startup folder is materialized at first logon, not at user creation)" note. |
| `docs/techniques/persistence/task-scheduler.md` | `scheduler.Create(\`\\\<name>\`, …)` "Simple" | lowuser cannot register a task at the root path; gets `RegisterTaskDefinition: Une exception s'est produite. (<nil>)` even with `WithTriggerLogon` | clarify-doc | TODO — add a "User-scope tasks live under `\Users\<sid>\` or similar; the root path requires admin/SYSTEM" note. Or document the correct path syntax for unprivileged installs (or note that there isn't one — task registration in the root namespace is admin-only on modern Windows). |
| `docs/techniques/persistence/account.md` | `import "github.com/oioio-space/maldev/persistence/account"` then uses `user.Add(...)` | works because the package declaration is `package user` — implicit alias from the import path's basename to the actual package identifier. The doc lists the import path but never explains the rename, easy to miss when the example doesn't compile in a casual reader's editor. | clarify-doc | TODO — show the import line with an explicit rename (`user "github.com/oioio-space/maldev/persistence/account"`), or rename the package to `account` to remove the surprise entirely. |
| `docs/techniques/cleanup/ads.md:Simple` | `streams, _ := ads.List(...)` shown as `[]string{"config"}` | actual return is a slice of structs with at least Name + Size (`[{config 10}]`) | fix-doc | TODO — show the real type in the comment and `for _, s := range streams { fmt.Println(s.Name, s.Size) }`. |
| `docs/techniques/credentials/goldenticket.md` | `Hash{EType: …, Bytes: …}` and `ETypeAES256CTSHMACSHA196`, `ETypeAES128CTSHMACSHA196` | real struct field is `Type` (not `EType`), real constants are `ETypeAES256CTS` / `ETypeAES128CTS` (no `HMACSHA196` suffix) | fix-doc | TODO — replace EType→Type in `Hash` and rename the constants in the comparison table to drop the bogus suffix. Three call-sites in the doc (lines 116, 166, 218). |
| `docs/techniques/credentials/lsassdump.md` | sentinel error routing (`ErrOpenDenied` for non-admin) | matrix evidence: lowuser hits `lsass.exe not found` (string-comparison miss vs the documented sentinel), Win11 admin hits `ErrOpenDenied` even though the cause is RunAsPPL (should be `ErrPPL`) | fix-code | TODO — tighten the error classification in the dump path so the documented sentinels actually fire when the documented condition holds. |
| `docs/techniques/credentials/samdump.md` `LiveDump` | matrix evidence: fails on all four cells with `samdump: live dump failed` (admin too) | unclear — LiveDump uses VSS shadow copies which may need explicit feature setup on workstation SKUs, or the function has an environment requirement the doc doesn't mention | clarify-doc + investigate-code | TODO — reproduce manually on the VM, capture the real underlying error, then either fix-code or add a "VSS required" note. |
| `docs/techniques/pe/certificate-theft.md:Simple` | `cert.Copy(\`C:\Windows\System32\notepad.exe\`, …)` | notepad.exe (and most modern system PEs) are *catalog-signed* — the Authenticode signature lives in `\System32\CatRoot\…\*.cat`, not embedded in the PE overlay. `cert.Has(notepad.exe)` returns false on Win10 + Win11; the example would fail at the source-cert read. | clarify-doc | TODO — change the example to a third-party signed PE (e.g. `\Program Files\Internet Explorer\iediagcmd.exe` historically had embedded sig, or a small embedded-signed Windows tool), or add a note explaining catalog vs embedded signing and how to inspect both. |
| `docs/techniques/process/session.md:Simple` | `i.SessionID`, `i.Username` | real fields on `session.Info` are `ID`, `Name`, `State`, `User`, `Domain` (no `SessionID`, no `Username`) | fix-doc | TODO — rewrite the example: `fmt.Printf("session %d (%s): %s\\%s (%v)\n", i.ID, i.Name, i.Domain, i.User, i.State)`. |
| `docs/techniques/collection/{clipboard,screenshot,keylogging}.md` | "Simple" examples imply they "just work" | every primitive needs an interactive logon session — running from a service / scheduled task / SSH session yields empty clipboard, "screen capture failed", and a keylogger that receives no events. Matrix evidence on Win10 + Win11 in both admin and lowuser. | clarify-doc | TODO — add a "Session requirement" callout to the area README: collection requires session ≠ 0 with an attached desktop. Useful for operators who would otherwise wonder why their service-mode implant collects nothing. |

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

### Panorama 3 — `recon-suite` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `antidebug.IsDebuggerPresent` | ✅ false | ✅ false | ✅ false | ✅ false | OK |
| `antivm.Detect` | ✅ "QEMU" | ✅ "QEMU" | ✅ "QEMU" | ✅ "QEMU" | OK — both VMs surface the QEMU vendor as expected |
| `sandbox.IsSandboxed` | ✅ "virtual machine detected" | ✅ same | ✅ same | ✅ same | OK |
| busy-wait timing | ✅ 200-206ms | ✅ same | ✅ | ✅ | OK |
| `drive.New("C:")` | ❌ "syntax incorrect" | ❌ same | ❌ same | ❌ same | **Doc bug** — needs trailing `\`. Example fixed locally to `\`C:\\\``. |
| `folder.GetKnown(FOLDERID_RoamingAppData…)` | ✅ `C:\Users\test\AppData\Roaming` | ✅ `C:\Users\lowuser…\AppData\Roaming` | ✅ | ✅ | OK — non-admin can resolve their own profile paths |
| `network.InterfaceIPs` | ✅ 4 IPs (link-local v6 + v4 + loopback ×2) | ✅ same | ✅ | ✅ | OK |
| `hwbp.Detect` | ✅ "no DR0-DR3 set" | ✅ same | ✅ | ✅ | OK; doc-drift on the Breakpoint field names (no `Module`/`TID`) |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | full panorama green |

Recon is observation-only — every check works at lowuser parity with admin, which matches expectations. The two doc bugs (drive.New signature, hwbp.Breakpoint fields) are pure typo-class fixes.

### Panorama 5 — `persistence-user` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `registry.Set(HiveCurrentUser, KeyRun, …)` + `Delete` | ✅ Set OK / Delete OK | ✅ same | ✅ | ✅ | OK — HKCU is per-user, no admin |
| `startup.Install("name", path, args)` + `Remove` | ✅ | ❌ `SHGetKnownFolderPath: file not found` | ✅ | ❌ same | Doc bug — `startup.Install` requires a materialized Shell folder, which the user only gets after a first interactive logon. |
| `scheduler.Create(\`\\name\`, WithTriggerLogon, WithHidden)` + `Delete` | ✅ | ❌ `RegisterTaskDefinition: exception` | ✅ | ❌ same | Doc bug — the example uses a root-namespace path, which requires admin. The doc should either steer to `\Users\<sid>\<name>` (still privileged on most builds) or call out admin as a prerequisite for the "Simple" form. |
| Process exit code | ✅ rc=0 | ✅ rc=0 (errors are reported, the example doesn't fatal) | ✅ rc=0 | ✅ rc=0 | OK |

This is the key admin/user differential the audit is designed to surface: the doc folder is named "persistence" but only **one of the three "Simple" examples actually works for an unprivileged user**. HKCU Run is the one truly user-scoped vector. The doc would benefit from a "What persists without admin" callout.

### Panorama 6 — `persistence-admin` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `user.Add` + `user.Delete` (account.md) | ✅ Add OK / Delete OK | ❌ `add user: access denied` | ✅ | ❌ same | OK — local-account creation is `NetUserAdd` which is admin-only |
| `service.Install` + `service.Uninstall` | ✅ both OK | ❌ `service.Install: access denied` | ✅ | ❌ same | OK — SCM `CreateService` is admin-only |
| `lnk.New().Save` to `C:\Users\Public\Desktop` | ✅ saved + cleanup OK | ❌ `Impossible d'enregistrer` (write-denied to Public Desktop) | ✅ | ❌ same | Default ACL on `C:\Users\Public\Desktop` is admin-write only on modern Win10/Win11 — clarify in lnk.md |
| Process exit code | ✅ rc=0 | ✅ rc=0 (errors are reported, not fatal) | ✅ rc=0 | ✅ rc=0 | OK |

The cleanest 3-for-3 / 0-for-3 differential in the audit. Combined with panorama 5 it gives the full "what persists without admin?" answer: only the HKCU Run key.

### Panorama 10 — `cleanup-suite` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `ads.Write` + `Read` (round-trip) | ✅ 10 bytes round-trip | ✅ same | ✅ | ✅ | OK |
| `ads.List` | ✅ `[{config 10}]` | ✅ same | ✅ | ✅ | Doc-drift: doc shows `[]string` |
| `ads.Delete` | ✅ | ✅ | ✅ | ✅ | OK |
| `timestomp.Set` (mtime+atime → 5y in past) | ✅ verified via os.Stat: 43800h ago | ✅ same | ✅ | ✅ | OK |
| `memory.SecureZero` | ✅ zeroed=true | ✅ | ✅ | ✅ | OK |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | full panorama green |

Anti-forensic primitives are filesystem-level (ADS via FILE_FLAG_BACKUP_SEMANTICS, timestomp via NtSetInformationFile FileBasicInformation, memory wipe is a process-local memset) — all work for any user with write access to the target file. The matrix uses `C:\Users\Public\maldev` which is granted to lowuser by the provisioning script.

### Panorama 4 — `unhook-suite` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `IsHooked` baseline (NtAlloc/NtCreateThreadEx/NtProtect) | ✅ all `hooked=false` | ✅ same | ✅ same | ✅ same | OK — clean VM, no EDR |
| `ClassicUnhook` × nil-caller (WinAPI fallback) | ✅ OK | ✅ same | ✅ | ✅ | OK |
| `ClassicUnhook` × `MethodIndirect`+`Tartarus` | ✅ OK | ✅ same | ✅ | ✅ | OK |
| `ClassicUnhook` × `MethodIndirectAsm`+`HashGate` | ✅ OK | ✅ same | ✅ | ✅ | OK |
| `FullUnhook(nil, nil)` | ✅ OK | ✅ same | ✅ | ✅ | OK — doc-warned "noisy" but does not fail |
| `PerunUnhook(nil)` (default child host) | ✅ OK | ✅ same | ✅ | ✅ | OK |
| `PerunUnhookTarget("svchost.exe", nil)` | ✅ OK | ✅ same | ✅ | ✅ | OK |
| `IsHooked` post-unhook | ✅ `hooked=false` | ✅ same | ✅ same | ✅ same | OK |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | full panorama green |

Notable: every unhook variant works at lowuser parity with admin, including `PerunUnhookTarget("svchost.exe")` which spawns a new child process to source the clean ntdll bytes — non-admin can spawn `svchost.exe` and read its memory because it's a *child* of the current process, not the system svchost. Doc and code aligned, no drift to flag.

### Panorama 7 — `tokens-impersonation` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `impersonate.ThreadEffectiveTokenOwner` | ✅ `…\test` | ✅ `…\lowuser` | ✅ same | ✅ same | OK |
| `privilege.IsAdmin` | ✅ `admin-group=true elevated=true` | ✅ `admin-group=false elevated=false` | ✅ | ✅ | OK |
| `privilege.IsAdminGroupMember` | ✅ `true` | ✅ `false` | ✅ | ✅ | OK |
| `token.StealByName("winlogon.exe")` | ✅ + IntegrityLevel = `System` | ❌ `open process: Accès refusé` | ✅ same | ❌ same | OK — SeDebugPrivilege required for SYSTEM, lowuser denied as expected |
| `token.StealByName("explorer.exe")` | ✅ + IntegrityLevel = `Medium` | ❌ `open process: Accès refusé` | ✅ same | ❌ same | OK — explorer owned by interactive `test`, different SID from lowuser |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | OK |

Cleanest "what can the current process see vs do" differential of the audit: every probe returns valid data for both modes, but the action (token steal) is admin-gated. Doc and code aligned across all checks.

### Panorama 8 — `privesc-uac` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `privilege.IsAdmin` | ✅ `admin-group=true elevated=true` | ✅ `admin-group=false elevated=false` | ✅ same | ✅ same | OK |
| `version.Current().BuildNumber` | ✅ 19045 (Win10 22H2) | ✅ same | ✅ 26200 (Win11) | ✅ same | OK |
| Composed-example branch decision | ✅ `not a UAC scenario` (already elevated) | ✅ `not a UAC scenario` (no admin group) | ✅ same | ✅ same | OK — both cells correctly early-out |
| `uac.FODHelper / SilentCleanup / EventVwr / SLUI` | API surface compiled, not exercised | not exercised | same | same | OK — test environment cannot produce Medium-IL admin via SSH |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | OK |

**Test-environment limitation**: a UAC bypass needs a *Medium-IL admin* shell (interactive RDP/console as a UAC-tagged admin who hasn't consented). SSH-launched `test` is automatically High-IL elevated; lowuser is not in the admin group at all. The matrix therefore validates the API surface and the gating logic, not the actual elevation. Doc's "Composed" example correctly anticipates this with `if elevated || !admin { return errors.New("not a UAC scenario") }`. Future work (out of audit scope): wire a Medium-IL launcher into the matrix runner.

### Panorama 9 — `credentials-suite` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `lsassdump.DumpToFile` | ✅ 644 regions / 58 MB / 94 modules | ❌ `lsass.exe not found` | ❌ `ErrOpenDenied` | ❌ `lsass.exe not found` | **2 findings.** (1) Win11 admin failing with ErrOpenDenied is consistent with default RunAsPPL — would be more accurate as ErrPPL. (2) Lowuser error is a string ("lsass.exe not found") not the documented `ErrOpenDenied` sentinel — sentinel routing is imprecise. |
| `samdump.LiveDump` | ❌ `live dump failed` | ❌ same | ❌ same | ❌ same | All 4 cells fail. Needs investigation — likely VSS feature gating or missing environment setup the doc doesn't mention. |
| `goldenticket.Forge` (offline crypto) | ✅ 1224-byte kirbi | ✅ same | ✅ | ✅ | OK — pure-Go forge needs no admin and no DC contact, exactly as the doc claims. |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | OK |

This row is the audit's most fix-rich panorama: 2 typo-class doc fixes for goldenticket, 1 fix-code for lsassdump's error classification, and 1 investigate-code for samdump.LiveDump. Despite the failures, the data still validates the documented threat model — admin-on-Win10-without-Credential-Guard is the only configuration where in-process LSASS mini-dump succeeds today.

### Panorama 11 — `pe-suite` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `imports.List(notepad.exe)` | ✅ 258 imports | ✅ same | ✅ 310 imports | ✅ same | OK — kernel32, user32, advapi32, etc., printed first 3 |
| `cert.Has(notepad.exe)` | ❌ false | ❌ false | ❌ false | ❌ false | **Doc-clarif** — notepad.exe is *catalog-signed* (`.cat` files in `\System32\CatRoot\…`), not Authenticode-embedded. The cert doc's "Simple" `cert.Copy(notepad.exe, …)` would fail at the source-read. |
| `cert.Read(notepad.exe)` | error: `PE file has no Authenticode certificate` | same | same | same | sentinel error fires correctly — code is right, doc example is misleading |
| `strip.Sanitize` | ✅ 201216 bytes in/out (delta=0) | ✅ same | ✅ 360448 in/out | ✅ same | OK — system PEs are already clean of Go pclntab / debug strings, so delta is naturally zero. Real implants would show non-zero delta. |
| `srdi.ConvertFile(notepad.exe)` | ✅ 228432-byte position-independent payload | ✅ same | ✅ 387664-byte | ✅ same | OK — pure transform, no privileged op |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | full panorama green |

PE work is parse + transform on raw bytes — no privileged syscalls, full parity admin/lowuser. The one quirk worth clarifying in the doc: modern Microsoft binaries use catalog signing, so the canonical example needs a different sample to actually exercise the cert-copy path.

### Panorama 12 — `process-tamper` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `enum.List` | ✅ 127 procs (sees lsass/winlogon/smss/csrss/services by PID+PPID+name) | ✅ 131 procs (same SYSTEM-owned procs visible by name) | ✅ 139 procs | ✅ 141 procs | OK — Toolhelp32 enumeration is name-level visibility, not handle-level. Both modes see SYSTEM-owned processes; only OpenProcess is gated. |
| `session.Active` | ✅ 1 session: `{ID:1 Name:Console State:Active User:test …}` | ⚠️ no rows printed | ✅ 1 session | ⚠️ no rows printed | Lowuser is invoked from a Schedule-Service session (session 0 batch logon) — `WTSEnumerateSessions` likely returns 0 rows or errors silently for that context. Worth a doc note. |
| `fakecmd.Spoof` + `Restore` | ✅ PEB rewritten to "svchost.exe -k netsvcs", restore OK | ✅ same | ✅ | ✅ same | OK — process-local PEB mutation, no admin needed. The doc says fakecmd targets a child process (the example shows `Spoof("...path...")` taking a string command-line); we exercised the self-process variant. |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | OK |

Notable: **fakecmd.Spoof works at lowuser parity with admin** — PEB rewriting is in-process memory tampering with no external token check, exactly the kind of evasion non-admin malware can rely on. Conversely, session enumeration's lowuser quirk (no rows visible) likely reflects the matrix runner's use of a session-0 scheduled task; an actual interactive user-session implant would see at least its own session.

### Panorama 13 — `collection-suite` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `clipboard.ReadText` | ✅ OK 0 chars | ✅ same | ✅ same | ✅ same | OK — no error, but no clipboard data either; session-0 has no user clipboard |
| `screenshot.Capture` | ❌ `screen capture failed` | ❌ same | ❌ same | ❌ same | Doc-clarif — needs interactive desktop |
| `keylog.Start` (100 ms window) | ✅ Start OK / 0 events drained | ✅ same | ✅ | ✅ | OK API surface, 0 events because session 0 has no input message pump |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | OK |

Single consolidated finding for the area: **collection requires an interactive logon session** (with an attached desktop and a window-station). Running from a service, scheduled task, or SSH session — which is how every "post-exploitation tool" actually lands on a target — yields empty/failed results. The doc should call this out at the top of the area README; right now the "Simple" examples make it look like one-line magic.

### Panorama 14 — `runtime-loaders` (matrix run, 2026-05-03)

| Step | win10 admin | win10 lowuser | win11 admin | win11 lowuser | Doc note |
|---|---|---|---|---|---|
| `bof.Load(nil)` (smoke-test invalid input) | ✅ structured error: `invalid COFF: data too small` | ✅ same | ✅ | ✅ | OK — error path is well-shaped |
| `clr.Load(nil)` | ❌ `ICorRuntimeHost unavailable (install .NET 3.5 and call InstallRuntimeActivationPolicy before Load)` | ❌ same | ❌ same | ❌ same | OK — known TOOLS-snapshot blocker (`clr_v2_activation_blocker` memory). Doc could mention the .NET 3.5 dependency more prominently in the Limitations block; the runtime-error message itself already does the right thing. |
| `inject.ModuleStomp("msftedit.dll", 1 byte)` | ✅ `addr=0x7fff35111000` | ✅ same address | ✅ Win11 distinct ASLR addr | ✅ same | OK — module stomping operates inside the implant's own address space (LoadLibrary + WriteProcessMemory(self) + flip-protection), no admin needed |
| Process exit code | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | ✅ rc=0 | OK |

ModuleStomp parity is the noteworthy result: a non-admin process can hijack a benign DLL inside its own image to host shellcode at a legit-looking RVA. Combined with the panorama-2 finding (preset.Stealth + ThreadPoolExec at parity), the audit now has two compounding lowuser-friendly building blocks for full in-process payload execution.

## Workflow per panorama

1. Pick the next ⏳ row in the backlog.
2. Read **only** the matching `docs/techniques/<area>/<file>.md` files (no source-code lookup) — this is the user's reproduction protocol.
3. Write `cmd/examples/<id>/main.go` and `docs/examples/<id>.md` from the docs.
4. `GOOS=windows go build ./cmd/examples/<id>/` — list every build error, mark as DOC-DRIFT in the running log above, decide fix-doc vs fix-code, patch the smallest set that compiles.
5. `vmtest -bin=cmd/examples/<id> -matrix windows windows11` (matrix flag added to runbin.go in this batch) — run admin + lowuser on both VMs.
6. Capture the matrix in this doc under "E2E observations".
7. Apply the doc/code fixes from steps 4 + 6. `/simplify` + skill check before commit.
8. Commit with a `panorama(<id>)` scope. Tick the row to ✅.
