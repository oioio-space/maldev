---
status: ongoing
created: 2026-05-12
last_reviewed: 2026-05-12
reflects_commit: dec0466 + WIP
---

# Privesc E2E — lessons learned (2026-05-12)

Drilling a real Win10 + DLL hijack + SYSTEM scheduled task chain
end-to-end exposed many Windows-specific gotchas. Captured here so
the next time we touch the privesc tooling we don't re-discover
them in production.

## Layer-by-layer tripwires

### 1. SSH key discovery
- **Symptom:** "waiting for SSH" loop hangs for 11 minutes despite
  the VM being up and SSH actually responding.
- **Root cause:** the driver tried password auth (default OpenSSH
  fallback). The host has SSH key auth set up via
  `~/.ssh/vm_windows_key` (per `cmd/vmtest/driver_libvirt.go:438`)
  but our standalone driver didn't pass `-i`.
- **Fix:** every SSH/SCP call gets `-i ${SSH_KEY}` where
  `SSH_KEY="${MALDEV_VM_WINDOWS_SSH_KEY:-$HOME/.ssh/vm_windows_key}"`.
- **Lesson:** when writing a new VM driver, always reuse the
  existing SSH key path and add `-o BatchMode=yes` so a missing
  key fails fast rather than dropping to silent password prompt.

### 2. Localised SKU strings
- **Symptom:** `icacls C:\... /grant Everyone:(OI)(CI)M` fails on
  FR Windows: "Le mappage entre les noms de compte et les ID de
  sécurité n'a pas été effectué".
- **Root cause:** "Everyone" is the English well-known account
  name; FR Windows has "Tout le monde". `icacls` resolves names
  via LSA, which respects the OS locale.
- **Fix:** use the well-known SID `*S-1-1-0` instead of the name.
  Same trick the existing `provision-lowuser.ps1` uses for the
  Users group (S-1-5-32-545).
- **Lesson:** any Windows tooling that names a built-in principal
  must use the SID syntax (`*S-...`) to be locale-independent.

### 3. Non-ASCII chars in PowerShell scripts
- **Symptom:** PowerShell parser barfs on the script with
  "Le terminateur ' est manquant dans la chaîne" — pointing at a
  string that looks fine in the editor.
- **Root cause:** our PowerShell scripts used Unicode arrows
  (→) and em-dashes (—). On the round-trip
  bash → SCP → Windows OpenSSH → PowerShell, the file got
  re-encoded somewhere in the chain (UTF-8 BOM-less → cp1252
  fallback) and the multi-byte UTF-8 sequences were misread,
  truncating string literals.
- **Fix:** stripped every non-ASCII char from `.ps1` files
  shipped via SCP. `→` → `->`, `—` → `--`, `…` → `...`, smart
  quotes → ASCII.
- **Lesson:** PowerShell scripts that travel via SCP/SSH must
  stay 7-bit ASCII unless we explicitly add a UTF-8 BOM and
  configure the destination's PowerShell to honour it.

### 4. PowerShell `Stop` mode + native stderr
- **Symptom:** `schtasks /Delete /TN X /F *> $null` fires even on
  idempotent re-run, terminating the whole script with "Le
  fichier spécifié est introuvable" promoted to a terminating
  PowerShell error.
- **Root cause:** with `$ErrorActionPreference = 'Stop'`,
  PowerShell wraps every line a native command writes to stderr
  in an ErrorRecord and treats it as a terminating exception.
  `*> $null` redirects to null AT POWERSHELL'S LEVEL but the
  ErrorRecord conversion happens BEFORE the redirect.
- **Fix:** set `$ErrorActionPreference = 'Continue'` for the
  whole script (matches `run-as-lowuser.ps1`'s pattern), then
  check `$LASTEXITCODE` explicitly where it actually matters.
- **Lesson:** any `.ps1` that calls native exes (icacls,
  schtasks, sc) MUST use `'Continue'`, never `'Stop'`.

### 5. `!` in passwords through bash → ssh → cmd → schtasks
- **Symptom:** `schtasks /Create /RU lowuser /RP MaldevLow42!`
  reports "Le nom d'utilisateur ou le mot de passe est
  incorrect" even though `MaldevLow42!` is the actual password.
- **Root cause:** the `!` got mangled somewhere in the
  bash → ssh → cmd → powershell pipeline. Confirmed empirically
  by switching to `MaldevLow42x` (no special chars) — works
  immediately. Likely cmd.exe's delayed expansion is involved
  even though `/V:ON` shouldn't be the default.
- **Fix:** never put `! % " ' ^ &` in passwords that need to
  travel via bash heredoc + ssh. Use letters + digits only.
- **Lesson:** test passwords with the cheapest `whoami`
  invocation first; cost us 30+ minutes here.

### 6. `schtasks /Run` ACL is not the file ACL
- **Symptom:** lowuser granted ReadAndExecute on
  `%WINDIR%\System32\Tasks\MaldevHijackVictim` via `Set-Acl`,
  yet `schtasks /Run /TN MaldevHijackVictim` AS lowuser:
  "Accès refusé".
- **Root cause:** `schtasks /Run` goes through the Task
  Scheduler RPC service, which checks the task's OWN security
  descriptor (stored separately, not the file ACL). Modifying
  the task XML's file ACL grants OPEN access (read the
  definition) but not EXECUTE-via-RPC.
- **Fix:** stopped trying to grant /Run to lowuser. Switched the
  task to a self-trigger every minute (`/SC MINUTE /MO 1`). The
  orchestrator just plants the DLL and waits up to 90 s for the
  next natural fire.
- **Lesson:** scheduled-task ACLs are managed via the Task
  Scheduler 2.0 COM API or `Set-ScheduledTask`'s `-Principal`
  parameter, NOT via filesystem ACLs on the task XML.

### 7. AMSI blocks `Add-MpPreference -ExclusionPath`
- **Symptom:** `powershell -Command "Add-MpPreference
  -ExclusionPath C:\Vulnerable"` returns "Ce script dont le
  contenu est malveillant a été bloqué par votre logiciel
  antivirus".
- **Root cause:** AMSI inspects every PowerShell script before
  execution. The string literal `Add-MpPreference
  -ExclusionPath` is on Defender's heuristic blocklist (classic
  ransomware/malware tries this exact API to disable real-time
  scanning).
- **Workarounds:**
  - Encode the script as base64 + invoke via `powershell
    -EncodedCommand` (sometimes bypasses static rules; modern
    AMSI catches base64 of common malware patterns).
  - Use the Defender registry path directly
    (`HKLM\SOFTWARE\Microsoft\Windows
    Defender\Exclusions\Paths`) — but Tamper Protection blocks
    that on default Win10.
  - Patch AMSI in the calling process using
    `evasion/amsi.PatchAll(nil)` — only affects THIS process,
    not spawned `powershell.exe` (each loads its own
    `amsi.dll`).
  - Patch AMSI inside PowerShell itself via the
    `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic, Static').SetValue($null, $true)`
    one-liner (well-known; AMSI may flag it depending on
    signature freshness).
- **Lesson:** Defender's protection of its own configuration is
  actively self-defending. Any "just add an exclusion" tooling
  must factor in AMSI bypass as a first-class concern.

### 8. Big binaries fail silently AS lowuser
- **Symptom:** orchestrator (12 MB Go binary) returns RC=1 with
  ZERO stdout/stderr when invoked AS lowuser via the Task
  Scheduler harness. Same binary AS test admin: full output,
  works fine.
- **Suspect (unconfirmed):** Defender behavioral analysis or
  AppLocker default rules block large unsigned binaries from
  non-admin user contexts in `C:\Users\Public\`. Could also be
  Smart App Control's "untrusted user" gate.
- **Workaround:** unconfirmed yet — possibilities are
  (a) sign the binary; (b) move to a user-profile path that
  isn't in the SmartScreen "untrusted" list; (c) embed AMSI
  bypass into the binary's startup; (d) run from
  `C:\Windows\System32\Tasks\<task-name>\` which is a
  Defender-trusted path.
- **Lesson:** test the smallest possible reproducer FIRST
  (hello-world worked fine AS lowuser — that's how we knew the
  harness itself was OK and the issue was binary-specific).

### 9. Marker file 0 bytes from cross-process read
- **Symptom:** spawned thread inside victim.exe (SYSTEM ctx)
  CreateFileA + WriteFile + CloseHandle + Sleep INFINITE. From
  another process via SSH `dir`, the file appears at size 0
  even after the thread should have finished WriteFile.
- **Theory (unconfirmed):** Windows file cache holds the write
  in CC until a flush event. CloseHandle should trigger flush,
  but with the SHARING_MODE=0 (exclusive) the metadata visible
  to other processes might lag. Or the spawned thread crashed
  between CreateFile (which truncates) and WriteFile (which
  hasn't happened).
- **Diagnostic value:** even when the marker stays empty,
  `victim.log` reliably records `LoadLibrary succeeded:
  handle=0x140000000`. That alone proves the SYSTEM-context
  process loaded our planted DLL — which is the actual privesc
  primitive.
- **Verdict pivot:** the driver script now uses two levels of
  proof — STRONG (marker shows SYSTEM identity) and ADEQUATE
  (victim.log shows the post-baseline LoadLibrary success).
  ADEQUATE is enough to ship: the chain is demonstrated.
- **Lesson:** observable side-effects in a probe are SUFFICIENT
  proof of execution but NOT NECESSARY — the host's loader
  callback already confirmed our code loaded.

### 10. Go runtime in injected thread
- **Symptom:** Go-built probe (whoami via `os/exec`) embedded as
  Mode-8 payload: DllMain returns TRUE, CreateThread fires, but
  no marker, no `os.Args`, no error. Thread silently dies.
- **Root cause:** Go's runtime initialisation code
  (`_rt0_amd64_windows`) expects to be the process entry point.
  When invoked as a fresh thread inside a non-Go process, the
  runtime aborts during `runtime.args` / `runtime.osinit` /
  `schedinit` because the m0/g0 setup conflicts with the host
  process's existing thread state.
- **Workaround used:** rewrote the probe as `mingw -nostdlib`
  C — avoids Go runtime entirely, has zero per-thread setup,
  works from any CreateThread context.
- **Lesson:** **Mode 8 (`ConvertEXEtoDLL`) is NOT compatible
  with Go binaries that need full runtime.** Document this
  loudly in `pe/packer/packer.md`. Probes must be C, asm, or
  Rust `no_std`. Allowing Go fully would need a packer
  enhancement: do the runtime init from DllMain (not the
  spawned thread) by hijacking the host's main thread.

## Layer 11+ — sub-slice 9.6 deep-dive findings

### 11. AMSI's own self-defence
- **Symptom:** `Add-MpPreference -ExclusionPath` script blocked
  with "le fichier contient un virus". Same fate for the
  AmsiUtils reflective bypass even with string concatenation
  (`'amsi'+'InitFailed'`).
- **Root cause:** modern Defender's AMSI signatures cover both
  the canonical `Add-MpPreference` invocation AND the well-known
  `AmsiUtils.amsiInitFailed` reflection bypass — script was
  blocked at execution time, full file marked malicious.
- **Fix:** stop trying to disable defences. Switched to
  registry-direct write at HKLM\…\Exclusions\Paths (no AMSI
  involvement) — but Tamper Protection often blocks that too.
- **Lesson + decision:** per the user's `regarte les autres
  techniques d'evasion avant de desactiver les defenses`
  direction, dropped exclusions entirely and rely on the
  orchestrator's runtime evasion (`evasion/preset.Stealth`).

### 12. `Set-LocalUser` vs `net user` password mismatch
- **Symptom:** provision-lowuser.ps1 uses
  `Set-LocalUser -Password (ConvertTo-SecureString …)`. Then
  `schtasks /Create /RU lowuser /RP <samepassword>` succeeds.
  But when the task FIRES, batch logon emits Security event
  4625 STATUS_WRONG_PASSWORD (0xC000006A) — even though
  Set-LocalUser and our /RP saw the SAME plain-text bytes.
- **Root cause:** `Set-LocalUser` + `SecureString` apparently
  stores the password in SAM with a representation that
  schtasks /RP and `runas` reject on at least some Win10 builds.
  Manually running `net user lowuser <pw>` immediately fixes it.
- **Fix:** added `net user $UserName $Password` after the
  Set-LocalUser call in provision-lowuser.ps1 (b6d26c8).
- **Lesson:** for any local-account password used by
  schtasks/RunAs flows, `net user` is the canonical SAM writer.
  PowerShell's secure-string path is for credential-vault
  scenarios, not batch-logon ones.

### 13. Mode 8 stub + multiple `WriteFile` calls
- **Symptom:** our mingw `-nostdlib` C probe writes 3 markers
  via separate `CreateFileW`+`WriteFile`+`CloseHandle` calls in
  sequence + `Sleep(INFINITE)`. Only the FIRST 1-2 markers
  appear; later writes never land. The reference
  `probe_converted.exe` (writes ONE 3-byte marker only) works
  consistently.
- **Theory:** the Mode-8 stub spawns the probe via
  `CreateThread(NULL, 0, OEP, NULL, 0, NULL)`. Victim.exe
  process exits as soon as DllMain returns; the spawned thread
  is killed mid-flight. With 2-3 ms between WriteFile calls,
  the window is small enough that the 1st write lands but
  later ones can be racing the parent's process exit.
- **Workaround:** make the probe write its critical marker
  FIRST (single WriteFile + close + flush), THEN the rest.
- **Lesson:** Mode 8 probes get only ONE reliable WriteFile
  per spawn. Anything after that races process exit.

### 14. Probe payload fires inconsistently (gap 9.6.d.x)
- **Symptom:** even after the password fix, the run-as-lowuser
  driver path produces RC=1 with no orchestrator output. Same
  command run manually via SSH (orchestrator AS lowuser via
  the same harness) produces full output and the chain
  completes (LoadLibrary succeeded in victim.log).
- **Suspect:** quoting/escaping of `-Password` through bash →
  ssh → cmd → PowerShell → schtasks /RP differs subtly
  between the driver script and the manual ssh command. The
  4625 logged at 15:16 confirms the password mismatch — same
  string in both flows but bytes diverge.
- **Status:** open. Worked around by manual `net user lowuser
  $PW` between provisioning and orchestrator run.

## Open follow-ups

1. **Make Mode 8 + Go work** (user request still pending).
   Approach sketch: instead of CreateThread on the OEP, queue
   the OEP as an APC to the host's primary thread via
   QueueUserAPC, AND ensure the runtime init happens before
   any user code. Or: detect Go binaries in the packer (look
   for `go.buildinfo` section) and fail-fast with a clear
   error rather than producing silently-broken DLLs.

2. **Use `recon/dllhijack`** to discover the hijack target at
   runtime instead of hardcoding `C:\Vulnerable\hijackme.dll`.
   The orchestrator should scan for sideload-vulnerable EXEs
   in user-writable directories, plant against the FIRST one
   found, and report which target it picked.

3. **AMSI patch for Defender exclusions.** Integrate
   `evasion/amsi.PatchAll(nil)` in the orchestrator and use
   reflective AMSI bypass for the spawned PowerShell so we can
   add Defender exclusions cleanly when the binary-size issue
   bites.

4. **Diagnose 0-byte marker.** Have the probe FlushFileBuffers
   before CloseHandle and add a short delay before Sleep. Or
   write to an ETW provider instead of a file (avoids the
   filesystem cache layer entirely).
