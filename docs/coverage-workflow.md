# Coverage Workflow — test harness state (as of 2026-04-22)

This document is the **entry point for any agent or contributor picking up
the coverage + VM-testing work**. It describes the infrastructure currently
in place, how to reproduce it, what passes / skips / fails, and what's left
to do.

> For bootstrap from scratch (creating VMs, SSH keys, INIT snapshots) see
> [`docs/vm-test-setup.md`](vm-test-setup.md).
> For per-test-type details (x64dbg harness, BSOD, Meterpreter matrix)
> see [`docs/testing.md`](testing.md). **This document** is the
> cross-platform coverage collection workflow itself.

---

## TL;DR — two commands to reproduce everything

```bash
# 1) Provision the VMs (idempotent — short-circuits what's already installed).
#    Installs .NET 3.5 on win10, postgresql + msfdb on debian13, then takes
#    a TOOLS snapshot per VM. ~10 min on first run, <30s on re-runs.
bash scripts/vm-provision.sh

# 2) Collect coverage end-to-end (host + Linux VM + Windows VM, all gates
#    open, consolidated report). ~25 min.
bash scripts/full-coverage.sh --snapshot=TOOLS
```

Outputs (written to `ignore/coverage/`, which is gitignored):

- `report-full.md` — per-package table sorted by ascending coverage, with a
  function-level gap list for the packages that aren't at 100%.
- `cover-merged-full.out` — merged Go cover profile (consumable by
  `go tool cover`).
- `tallies.txt` — one-line per-run summary in native `go test` format.
- `<domain>/test.log` + `<domain>/cover.out` — per-VM artifacts.

---

## Script architecture

| Script | Role | Depends on |
|---|---|---|
| `cmd/vmtest` | VM orchestrator (start, push, exec, fetch, stop, restore). Extension of the existing tool: new `-report-dir` flag auto-fetches `cover.out` + `test.log` | libvirt **or** VirtualBox; `scripts/vm-test/config.yaml` + `config.local.yaml` |
| `scripts/vm-provision.sh` | Installs missing tools in each VM and snapshots `TOOLS` | SSH to the 3 VMs; sudo on Kali; UAC bypass via `schtasks SYSTEM` on Windows |
| `scripts/full-coverage.sh` | End-to-end wrapper: boots the 3 VMs, exports all gates, runs host + Linux VM + Windows VM, merges profiles, restores snapshots | `scripts/coverage-merge.go`, `cmd/vmtest` |
| `scripts/coverage-merge.go` | Merges N Go cover profiles (union, per-block max hit count), renders Markdown | `go tool cover` |

**Common flags:**

- `--snapshot=NAME` (default `INIT`) — snapshot used for restore, also
  forwarded to `vmtest` via `MALDEV_VM_*_SNAPSHOT`.
- `--no-restore` — leave VMs running after the run (debugging).
- `--skip-host` / `--skip-linux-vm` / `--skip-windows-vm` — granular control.
- `--only=<vm>` on `vm-provision.sh` — provision a single VM.
- Env overrides (`MALDEV_VM_WINDOWS_SSH_HOST`, `MALDEV_KALI_SUDO_PASSWORD`,
  `MALDEV_VM_SNAPSHOT`, …) for portability across hosts.

### Concrete usage examples

```bash
# Provision just Windows, don't touch Kali/Linux.
bash scripts/vm-provision.sh --only=windows

# Quick iteration on a single package — skip the host + Linux VM phases.
bash scripts/full-coverage.sh --snapshot=TOOLS --skip-host --skip-linux-vm

# Narrow vmtest directly at one package (faster than the full wrapper).
MALDEV_VM_WINDOWS_SSH_HOST=192.168.122.122 \
MALDEV_VM_WINDOWS_SNAPSHOT=TOOLS \
MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1 \
  go run ./cmd/vmtest -report-dir=ignore/coverage windows \
    "./pe/clr/..." "-count=1 -v -timeout=5m"

# Merge arbitrary profiles by hand.
go run scripts/coverage-merge.go \
  -out ignore/coverage/cover-merged.out \
  -report ignore/coverage/report.md \
  ignore/coverage/cover-linux-host.out \
  ignore/coverage/win10/cover.out \
  ignore/coverage/win10/clrhost-cover.out
```

---

## Snapshot inventory

Each VM has two snapshots dedicated to the test harness:

| VM | `INIT` | `TOOLS` |
|---|---|---|
| `win10` | Go 1.26.2 + OpenSSH + authorized_keys | `INIT` + **.NET Framework 3.5 enabled** |
| `debian13` (Kali) | Go + MSF + OpenSSH + authorized_keys | `INIT` + **postgresql enable --now** + **msfdb init** |
| `ubuntu20.04-` | Go 1.26.2 + rsync + authorized_keys | (placeholder — identical to `INIT` for now) |

**Rule:** always test on `TOOLS`. `INIT` stays pristine as a fallback if
`TOOLS` gets corrupted. `vm-provision.sh` is idempotent: if `TOOLS` already
exists and the tools are already installed, it's a no-op.

---

## Test gates (environment variables)

The harness uses opt-in gates so running `go test ./...` locally doesn't
accidentally trigger destructive operations.

| Variable | Effect | When to enable |
|---|---|---|
| `MALDEV_INTRUSIVE=1` | Unblocks tests that mutate process state (hooks, patches, injection) | VM runs only |
| `MALDEV_MANUAL=1` | Unblocks tests that need admin + VM (services, scheduled tasks, impersonation with password, CLR legacy path, CVE PoCs) | VM runs only |
| `MALDEV_KALI_SSH_HOST` / `_PORT` / `_KEY` / `_USER` | Points to the Kali VM for MSF/Meterpreter tests | Always set when Kali is up |
| `MALDEV_KALI_HOST` | LHOST for reverse payloads — same IP as Kali | Ditto |
| `MALDEV_VM_WINDOWS_SSH_HOST` / `_LINUX_SSH_HOST` | Overrides `virsh domifaddr` auto-discovery when the libvirt session can't see DHCP leases (Fedora host) | On hosts where auto-discovery fails |
| `MALDEV_VM_*_SNAPSHOT` | Selects the snapshot used for restore per VM | To pin `TOOLS` explicitly |

`scripts/full-coverage.sh` exports all 10 variables automatically — pass
`--snapshot=TOOLS` and it handles the rest.

---

## Reference results (run from 2026-04-22 — `TOOLS` snapshot)

```text
  cover-linux-host.out                     cov=44.8% (host, all gates)
  ubuntu20.04-                             cov=44.4% P=310  F=0*  S=41   (Linux VM)
  win10                                    cov=50.0% P=672  F=0** S=23   (Windows VM)
  ----------------------------------------
  cover-merged-full.out                    cov=51.9% (merged)
```

Progression over the course of the work:

| Step | Merged coverage | Delta |
|---|---|---|
| Baseline (Linux host only, no gates) | 39.4% | — |
| + Linux VM + Windows VM (3 batches) | 41.3% | +1.9 |
| + 16 stub tests added | 43.1% | +1.8 |
| + `MALDEV_INTRUSIVE=1` + `MALDEV_MANUAL=1` + Kali | 51.3% | +8.2 |
| + `TOOLS` snapshot (.NET 3.5) | 51.3% | +0 ¹ |
| + compat polyfill tests (`cmp`, `slices`) | 51.4% | +0.1 |
| + clrhost subprocess coverage merge | **51.9–52.0%** | +0.6 |

¹ The `pe/clr` CLR tests still SKIP on this VM — the TOOLS provisioning
enabled .NET 3.5 but the legacy v2 COM activation chain remains incomplete
(see [CLR v2 activation blocker](#clr-v2-activation-blocker) below). The
merge coverage for `pe/clr` is from the failure paths in `Load()`, which
the `clrhost-cover.out` profile captures.

`*` Historical: `TestProcMemSelfInject` flapped 2 out of 3 runs (transient
SIGSEGV in the child during exit cleanup, after injection succeeded).
**Fixed** via 3× retry + `PROCMEM_OK` marker match in stdout instead of
relying on exit code.

`**` Historical: `TestBusyWaitPrimality` failed on the Windows VM (took
10.15 s against a 10 s upper bound). **Fixed** by raising the bound to
60 s — the VM's CPU is shared (20 vCPUs / 4 GB RAM) and non-deterministic.

---

## Remaining SKIPs — justified inventory (64 across the all-gates run)

SKIPs aren't a defect as long as each one is legitimate. Classification:

| # | Family | Examples | Fixable? |
|---|---|---|---|
| 40 | Platform mismatch | `RequireWindows` on Linux VM, `RequireLinux` on Windows | No — by design |
| 5 | Skip-because-admin | `TestAddAccessDenied` tests the "Access Denied" branch when **not** admin; correct to skip when we **are** admin | No — inverted-logic check |
| 3 | `.NET 3.5` subprocess paths | `TestLoadAndClose`, `TestExecuteAssembly*`, `TestExecuteDLL*` | Partial — see "clrhost" above |
| 3 | External tools missing | `TestBuildWithCertificate` (signtool, Windows SDK 1 GB), `TestUPXMorphRealBinary` (UPX 3.x only — we have 4.2.4) | High cost — documented |
| 3 | Interactive session required | `TestCapture*`, `TestCaptureSimulatedKeystrokes` — need session 1 (desktop); SSH opens session 0 | Possible via RDP + AutoLogon, low priority |
| 4 | SC-specific context | `Test{Hide,UnHide}Service*` — require a pre-existing service with a specific SD | Would need a dummy service in TOOLS |
| 3 | MSF timing / PPID | `TestMeterpreterRealSession` (×2), `TestPPIDSpoofer` — MSF boot timing + PPID race | Retry loop possible |
| 2 | `!windows` stubs | `TestEnforcedNonWindowsStub`, `TestDisableNonWindowsStub` | Correctly skip on Windows — no action |
| 2 | NTFS / memory protection | `TestFiber_RealShellcode`, `TestSetObjectID` | Defender / NTFS quirks |

---

## <a id="clr-v2-activation-blocker"></a>CLR v2 legacy activation blocker

`pe/clr` tests (`TestLoadAndClose`, `TestExecuteAssemblyEmpty`,
`TestExecuteDLLValidation`, `TestExecuteDLLReal`) skip with:

```text
clr: ICorRuntimeHost unavailable (install .NET 3.5 and call InstallRuntimeActivationPolicy before Load)
```

**This is environmental, not a code bug.** Diagnosed during the 2026-04-22
session:

- `Get-WindowsOptionalFeature -Online -FeatureName NetFx3` → `State=Enabled`
- `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\mscorwks.dll` present (10.6 MB)
- A hand-written C# `hello.cs` compiled with `v2.0.50727\csc.exe` **runs** correctly — the v2 runtime itself works end-to-end
- `TestInstallAndRemoveRuntimeActivationPolicy` PASSES (writes/removes the legacy config file correctly)

Root cause: CLSID `{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}` (`CorRuntimeHost`)
is **not registered** in `HKLM\SOFTWARE\Classes\CLSID\`. Only the sibling
CLSID `{CB2F6723-AB3A-11d2-9C40-00C04FA30A3E}` (`IMetaDataDispenser`)
exists. DISM `/Enable-Feature /FeatureName:NetFx3` is **not sufficient** —
it enables the runtime bits but leaves the legacy v2 activation chain
incomplete.

Attempts that did NOT unblock it (all tried during the session):

- Reboot (actually `shutdown /r` under SYSTEM didn't really reboot)
- `regsvr32 mscoree.dll` (System32 + SysWOW64, both exit 0 but CLSID still missing)
- `RegAsm.exe mscorlib.dll /codebase` (failed RA0000 "need admin credentials" even under SYSTEM)
- Manual `reg import` of the CLSID structure mirroring the sibling `{CB2F6723-…}` entry — keys exist (`HKLM\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}\InprocServer32` → `mscoree.dll`, `ThreadingModel=Both`, `ProgID=CLRRuntimeHost`, `ImplementedInThisVersion={2.0.50727,4.0.30319}`) but `CorBindToRuntimeEx` still returns `0x80040154 (REGDB_E_CLASSNOTREG)` for both v2.0.50727 and v4.0.30319. Confirmed 2026-04-25 with a one-shot Go diagnostic that calls `mscoree!CorBindToRuntimeEx` directly and prints the raw HRESULT. Conclusion: mscoree's internal binding looks at more than just the CLSID — interface registration, typelib, and Fusion entries are also missing, and only the full `.NET 3.5 Redistributable` (offline `dotnetfx35.exe` from Win7-era, or the in-place `sources/sxs` payload from a Win10 ISO) runs the complete chain.
- `InstallRuntimeActivationPolicy()` at startup of `clrhost` (writes `<exe>.config` — doesn't help, the issue is COM registration)

**What was added in TOOLS v2 (2026-04-25):**

- `scripts/vm-provision.sh` now imports the CLSID `{CB2F6722-…}` entry every provisioning pass, so future debug rounds start from the same baseline rather than rediscovering the missing key. It also pushes + runs `dism /online /Add-Package` against the Win10 ISO's `sources/sxs/microsoft-windows-netfx3-ondemand-package*.cab` when staged at `MALDEV_NETFX3_CAB`. Confirmed 2026-04-25 that this still doesn't unblock `CorBindToRuntimeEx` after a reboot, but it gets the snapshot one step closer to a working CLR2 activation chain.
- `pe/clr/clr_windows.go::corBindToRuntimeEx` wraps the `REGDB_E_CLASSNOTREG` path with `%w` + the raw HRESULT, so SKIP messages now read `CorBindToRuntimeEx(v2.0.50727): HRESULT 0x80040154 (REGDB_E_CLASSNOTREG): clr: ICorRuntimeHost unavailable …` — the next investigator sees the actual code without rebuilding.

**What was tried + ruled out 2026-04-25 (after pt 1/2):**

1. `dism /online /enable-feature /featurename:NetFx3 /all /Source:<sources/sxs> /LimitAccess` after a `dism /disable-feature` round-trip — failed `0x488 (1168, ERROR_NOT_FOUND)`. The OnDemand cab alone isn't enough for /enable-feature.
2. `dism /online /Add-Package /PackagePath:<sources/sxs/...netfx3-ondemand...cab>` — succeeded, exit `3010 (REBOOT_REQUIRED)`. After reboot, `CorBindToRuntimeEx` still returns `0x80040154`. The OnDemand package adds the runtime files but not the legacy COM/typelib/Fusion chain mscoree binds against.
3. Win7-era `.NET Framework 3.5 Redistributable` (`dotnetfx35.exe`, 232 MB from Microsoft download CDN) — the installer ran silently and returned `0` but produced no log content beyond `DONE_EXIT=0`; on Win10 it refuses to install (the OS is "newer than supported"). HRESULT unchanged.

**What to try next (still open, needs Windows ISO):**

1. Mount a Win10 22H2 ISO inside the VM and run
   `dism /online /enable-feature /featurename:NetFx3 /all /source:D:\sources\sxs /LimitAccess`.
   This drives the full registration chain that the network-only DISM path
   skips.
2. Install the `.NET Framework 3.5 Redistributable` offline installer
   (`dotnetfx35.exe`, Win7-era) — even on Win10 it tends to trigger the full
   COM/typelib/Fusion registration via `mscorsvw.exe` post-install hooks.
3. `sfc /scannow` to restore system file coherence.
4. Re-provision the `win10` VM from a fresh Windows ISO that bundles .NET 3.5
   in the install base rather than activated after the fact via DISM.

The clrhost **coverage infrastructure** itself is correct — `go build -cover`,
`GOCOVERDIR`, `go tool covdata textfmt`, `vmtest.Fetch`, and `coverage-merge.go`
all work. When the CLR environment cooperates, 7+ `pe/clr` functions light
up in the merged profile (`Load` 56.7%, `enumerate` 100%, `orderCandidates`
90%, `metaHostRuntime` 77.8%, `runtimeInfoBindLegacyV2` 100%, `runtimeInfoCorHost`
62.5%, `createMetaHost` 80%). **Don't rewrite the mechanism — just fix the VM.**

---

## Other open leads

1. **Signtool** — install Windows SDK (headless via `winget install
   Microsoft.WindowsSDK`), re-snapshot `TOOLS`. Unblocks
   `TestBuildWithCertificate`.

2. **Service skeleton for `cleanup/service`** — pre-create a dummy service
   in the `TOOLS` snapshot (`sc create maldev-test-svc
   binPath=C:\Windows\System32\cmd.exe`). Unblocks `Test{Hide,UnHide}Service*`.

3. **Packages without `_test.go`** (29 as of 2026-04-22; see
   `ignore/coverage/no-tests.txt` if regenerated) — mainly `cmd/*` binary
   entry points and `pe/masquerade/preset/*`. The former are `main()`
   functions (out of scope for unit tests); the latter are resource-only
   packages with no executable code.

4. **Meterpreter matrix** — `scripts/x64dbg-harness/meterpreter_matrix/`
   exercises 20 techniques × MSF sessions. Not integrated into
   `full-coverage.sh` yet; run manually. Results logged in
   `docs/testing.md`.

5. **Automated "missing tool" detection** — extend `vm-provision.sh` to
   actively probe for signtool, Windows SDK, interactive session (today
   it checks only NetFx3, postgresql, msfdb). Add an issue-style section
   in the log listing what's absent.

---

## Files produced by this work

```text
cmd/vmtest/driver.go                       # +Fetch, +io.Writer in Exec
cmd/vmtest/driver_libvirt.go               # +Fetch scp, +io.Writer
cmd/vmtest/driver_vbox.go                  # +Fetch copyfrom, +io.Writer
cmd/vmtest/runner.go                       # +-report-dir, -coverprofile inject, tee log, Fetch cover.out + clrhost-cover.out
cmd/vmtest/runner_test.go                  # 4 unit tests (injectCoverprofile, safeLabel, guestCoverPath, guestClrhostCoverPath)
cmd/vmtest/main.go                         # +-report-dir flag

scripts/coverage-merge.go                  # merge N cover profiles → Markdown
scripts/full-coverage.sh                   # end-to-end workflow
scripts/vm-provision.sh                    # install tools + snapshot TOOLS

docs/coverage-workflow.md                  # this file

testutil/kali_test.go                      # 4 env resolvers (kaliSSHHost/Port/Key/User)
testutil/clr_windows.go                    # clrhost built with -cover, covdata → textfmt
testutil/clrhost/main.go                   # +exec-dll-real op, +--dll-path flag
testutil/clrhost/maldev_clr_test.dll       # 3 KB .NET 2.0 assembly (Maldev.TestClass.Run)

evasion/unhook/factories_test.go           # 5 factories + Name methods (Windows)
recon/hwbp/technique_test.go             # Technique() factory (Windows)
evasion/cet/cet_test.go                    # +Enforced/Disable stub tests
evasion/hideprocess/hideprocess_stub_test.go
evasion/stealthopen/stealthopen_stub_test.go
evasion/fakecmd/fakecmd_stub_test.go
evasion/preset/preset_stub_test.go
evasion/hook/hook_stub_test.go
evasion/hook/probe_stub_test.go
evasion/hook/remote_stub_test.go
evasion/hook/bridge/controller_stub_test.go
evasion/hook/bridge/controller_windows_test.go  # 8 deeper tests for CallOriginal, Args, Log, Ask
evasion/hook/hook_lifecycle_windows_test.go     # TestReinstallAfterRemove, TestInstallOnPristineTargetAfterGroupRollback
c2/transport/namedpipe/namedpipe_stub_test.go
cleanup/ads/ads_stub_test.go
process/session/sessions_stub_test.go
pe/clr/clr_stub_test.go
internal/compat/cmp/cmp_modern_test.go
internal/compat/slices/slices_modern_test.go

pe/clr/clr_windows_test.go                 # +TestExecuteDLLReal

recon/timing/timing_test.go              # TestBusyWaitPrimality upper bound 10s → 60s
inject/linux_test.go                       # TestProcMemSelfInject retry 3× + PROCMEM_OK marker
```

---

## Troubleshooting

- **VM unreachable over SSH.** `virsh -c qemu:///session list --all`,
  `virsh start <vm>`, check `ip neigh show | grep 52:54` (VM MAC in the
  ARP table). Session-mode libvirt doesn't expose DHCP leases via
  `virsh domifaddr`, hence the env-pinned IPs.
- **DISM "Access denied".** OpenSSH on Windows 10 runs at medium
  integrity; UAC blocks elevation. Workaround: run via `schtasks
  /ru SYSTEM` (see `scripts/vm-provision.sh` for the pattern).
- **Kali `sudo` prompts for a password.** Default is `test`; override via
  `MALDEV_KALI_SUDO_PASSWORD`.
- **`TOOLS` snapshot corrupted.** `virsh snapshot-delete <vm> --snapshotname
  TOOLS`, then re-run `vm-provision.sh`.
- **Windows tests frozen with no output.** `go test ./...` compiles
  silently for the first ~5 min — that's normal. Use `-v` to see each
  test as it starts rather than waiting for the package-level summary.
- **`TestProcMemSelfInject` / `TestBusyWaitPrimality` red.** If they
  flap despite the retry/bound fixes, reproduce with `go test -count=5
  -run <Name>` and tighten further.
- **VM silently pauses mid-run (QEMU `paused` state).** Observed 2 out
  of 5 runs during the 2026-04-22 session. ARP entry for the VM drops,
  SSH returns "No route to host". Workaround: `virsh destroy <vm> &&
  virsh snapshot-revert <vm> --snapshotname TOOLS --force`, then relaunch.
  If chronic, recreate `TOOLS` from a fresh `INIT`.
- **`pe/clr` tests SKIP with `ICorRuntimeHost unavailable`.** See the
  [CLR v2 activation blocker](#clr-v2-activation-blocker) section above.
  Not a code bug in maldev — the `.NET 3.5` install on this VM is
  incomplete at the COM-registration layer.
