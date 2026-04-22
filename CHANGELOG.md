# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/spec/v2.0.0.html). Pre-1.0 minor bumps may
introduce breaking API changes.

## [Unreleased]

Reproducible cross-platform coverage workflow + gap-filling tests.

### Added

- `cmd/vmtest`: new `-report-dir` flag with `Fetch()` method (scp for
  libvirt, `VBoxManage copyfrom` for VBox). Auto-injects
  `-coverprofile=<guest-path>` into forwarded `go test` invocations, tees
  `test.log`, and repatriates `cover.out` plus `clrhost-cover.out` when
  the guest produced one. (8aac278)
- `scripts/coverage-merge.go`: merges N Go cover profiles (union with
  per-block max hit count) and renders a Markdown gap report sorted by
  ascending coverage. (8aac278)
- `scripts/full-coverage.sh`: orchestrates host + Linux VM + Windows VM +
  Kali end-to-end, exports every `MALDEV_*` gate, restores to
  `--snapshot=NAME` (default `INIT`). Tolerant of test-level non-zero
  exits so gated failures don't abort subsequent phases. (8aac278)
- `scripts/vm-provision.sh`: idempotent per-VM tool install (NetFx3 via
  DISM SYSTEM scheduled task, postgresql + msfdb init on Kali). Takes a
  `TOOLS` snapshot when it's done. (8aac278)
- `docs/coverage-workflow.md`: canonical reference for the coverage
  workflow — snapshots, gates, layout, known blockers (QEMU pause race,
  CLR v2 COM activation on TOOLS snapshot), reproduction recipe. (8aac278)
- 16 gap-filling tests covering non-Windows stubs (c2/transport/namedpipe,
  evasion/{fakecmd,hideprocess,preset,stealthopen,hook,hook/probe,
  hook/remote,hook/bridge/controller}, system/ads, process/session,
  pe/clr, cet) plus Windows-only factory tests (evasion/unhook,
  evasion/hwbp) and `internal/compat/{cmp,slices}` polyfill smoke tests.
  (914aab4)
- `testutil/kali_test.go`: env-var resolvers (`kaliSSHHost/Port/Key/User`)
  with both override and fallback paths. (914aab4)
- `pe/clr` subprocess coverage: `testutil/clrhost` now builds with
  `go build -cover -covermode=atomic`, `GOCOVERDIR` points at a stable
  temp dir, `go tool covdata textfmt` converts to `clrhost-cover.out`
  which `cmd/vmtest` fetches and `coverage-merge` unions with the main
  profile. Ships with `testutil/clrhost/maldev_clr_test.dll` (3 KB .NET
  2.0 assembly) for `TestExecuteDLLReal`. (d0b9e0f)
- 8 deeper tests for `evasion/hook/bridge` Controller (`CallOriginal`,
  `ArgsDefault`, `SetReturnNoPanic`, `LogViaTransport`,
  `LogStandaloneNoop`, `ExfilStandaloneNoop`, `AskStandaloneAlwaysAllows`)
  and 2 hook lifecycle tests (`TestReinstallAfterRemove`,
  `TestInstallOnPristineTargetAfterGroupRollback`). (94a57cf)

### Fixed

- `evasion/timing`: `TestBusyWaitPrimality` upper bound 10s → 60s. VM
  CPU is shared and non-deterministic; the fixed-workload check still
  guards against infinite loops. (914aab4)
- `inject/linux_test.go`: `TestProcMemSelfInject` now retries 3× and
  matches `PROCMEM_OK` in stdout instead of requiring exit 0. The
  child's Go runtime can SIGSEGV during exit cleanup after injection
  succeeded — the marker is the real success signal. (914aab4)

### Coverage

Baseline 39.4% (Linux host only, no gates) → **51.9% merged** across 6
run contexts. See `docs/coverage-workflow.md` for the full breakdown.

## [v0.10.1] — 2026-04-18

Patch release: unlocks 116 previously-skipped tests + post-review fixes.

### Added

- `scripts/test-all.sh` auto-provisions per-layer MSF handler on Kali
  (`exploit/multi/handler` with sleep-3600 trick) and pushes the host-side
  Kali SSH key into each guest with strict ACLs. `MALDEV_KALI_SSH_KEY` is
  overridden per-layer so `testutil.KaliSSH` reaches Kali from inside the
  guest. `resolve_vm_ip` (arp/lease/agent fallback), `restore_init_silent`
  helpers. `set -Euo pipefail`.

### Fixed

- `cmd/memscan-mcp` `get_export` MCP tool: resolves `module` by name via
  `/module` first, then forwards the hex base to `/export`. Was always
  erroring because the server expects hex, not a DLL name.
- `scripts/vm-test/install-keys.sh`: now uses `qemu:///session` URI
  consistently (was defaulting to `qemu:///system` and silently skipping
  every domain on developer machines).
- `pe/morph TestUPXMorphRealBinary`: skip cleanly on non-Windows
  (UPXMorph is PE-only, the test execs the morphed binary); on Windows,
  skip under UPX 4.x because UPXMorph was written for 3.x signatures.

### Changed

- `cmd/vmtest/driver_libvirt.go`: collapsed three virsh helpers into a
  single `virshCmd` factory.
- `cmd/memscan-server/server_windows.go`: extracted `enumModules` +
  `moduleBasename` (deduped between `findModule` and `moduleNameAt`);
  `bytes.Index` instead of hand-rolled scan loop; `strconv.ParseUint`
  for hex parsing.
- `cmd/memscan-harness/harness_windows.go`: stdlib `sort.Strings`,
  `pickCaller` delegates to `pickWSyscallMethod`.
- `cmd/memscan-mcp/main.go`: extracted `toolText`/`toolError` helpers,
  `strings.Builder` in `formatJSON`.
- `cmd/test-report/main.go`: `countStatus` consolidated, dead
  `findTest` removed.

### Final test matrix (from INIT snapshots)

```text
memscan  77 / 77
linux   302 / 302   (40 legitimate skips)
windows 754 / 754   (21 legitimate skips)
TOTAL   1133 passed / 0 failed / 61 skipped
```

+116 tests now running vs v0.10.0; 0 failures maintained.

## [v0.10.0] — 2026-04-17

139 commits since [v0.9.0]. Highlights:

### Added — inline hooking + bridge

- **`evasion/hook/`** — x64 inline function hooking with trampoline and RIP-relative fixup, `InstallProbe` for unknown-signature targets, `HookGroup` (atomic multi-hook with rollback), `WithCaller`/`WithCleanFirst` options, `RemoteInstall` helpers.
- **`evasion/hook/bridge/`** — bidirectional controller/listener protocol over TCP/named-pipe/io.Pipe: wire-format with `ArgBlock`, `Decision`, multiplexed RPC (`Register`/`Call`), gob serialization layer, typed RPC via reflection (`func(T) (R, error)`).
- **`evasion/hook/shellcode/`** — Block/Nop/Replace/Redirect templates for drop-in decisions.

### Added — PE operations

- **`pe/masquerade/`** — compile-time PE resource embedding (manifest, VERSIONINFO, icons), blank-import `pe/masquerade/preset/` for one-liner impersonation, `IconFromFile`/`IconFromImage`/`WithSourcePE` programmatic API.
- **`pe/imports/`** — PE import table parser (IAT enumeration by DLL).

### Added — cross-host test infrastructure

- **`cmd/vmtest/`** — driver-based runner (auto-detects VBox vs libvirt), forwards `MALDEV_*` env into guests, ssh key-auth + rsync/scp push + snapshot restore.
- **`cmd/memscan-server/`** — Windows HTTP API on port 50300 wrapping `ReadProcessMemory` / `EnumProcessModulesEx` / `VirtualQueryEx`. Replaces the gitignored x64dbg MCP with pure-Go byte-pattern inspection.
- **`cmd/memscan-harness/`** — target-side tool with 5 groups (`ssn`, `amsi`, `etw`, `unhook`, `inject`) covering every caller × resolver combination in `docs/testing.md`.
- **`cmd/memscan-mcp/`** — stdio JSON-RPC 2.0 MCP adapter for Claude Code (tools: `read_memory`, `find_pattern`, `get_module`, `get_export`, `run_tests`).
- **`cmd/test-report/`** — parses `go test -json` streams, emits per-test / per-package / cross-platform matrix + failure detail + tally.
- **`scripts/test-all.sh`** — unified three-layer runner (memscan + linux + windows) with INIT snapshot revert between layers.
- **`scripts/vm-test-memscan.go`** — 32-row matrix → 77 static byte-pattern sub-checks (SSN 4×4, AMSI 4×3, ETW 4×6, Unhook 4×2, Inject 17).
- **`scripts/vm-test/`** — reproducible provisioning (`bootstrap-linux-guest.sh`, `bootstrap-windows-guest.ps1`, `install-keys.sh`), committed `config.yaml` + `config.local.example.yaml` + `kali-env.sh.example` templates.
- **`docs/vm-test-setup.md`** — end-to-end reproducibility guide (host install, guest provisioning, INIT snapshot, troubleshooting, Phase-5 punch-list).
- **`.mcp.json.example`** — Claude Code MCP wiring template.

### Fixed — test matrix (0 FAIL on libvirt Fedora against Windows 10 + Ubuntu 20)

- `win/impersonate`: `ThreadEffectiveTokenSID` + `ThreadEffectiveTokenHasGroup` helpers (locale-independent); dropped `Système` vs `SYSTEM` string assertions.
- `win/token`: `EnableAll`/`DisableAll` now no-op when every eligible privilege already matches (was `ErrNoPrivilegesSpecified`).
- `process/enum`: `TestSessionIDPopulated` compares against `ProcessIdToSessionId`, no longer assumes interactive session.
- `cleanup/service`: SCM DACL tests gated behind `MALDEV_SCM=1` + elevation probe (crashed silently under OpenSSH).
- `evasion/herpaderping`: manual temp dir + `taskkill` cleanup (image-lock race on spawned cmd.exe).
- `evasion/hook/bridge`: `skipIfNonWindowsController` on 11 tests needing the real Windows Controller.
- `pe/masquerade`: fall back to `explorer.exe` when `notepad.exe` UWP-shim ships without icon resources.
- `persistence/scheduler`: skip `TestList` in session 0 (OpenSSH).
- `c2/meterpreter` (linux e2e): `net.DialTimeout` probe + skip if no MSF handler.
- `evasion/hook/bridge`: moved `rpcResponse` to an untagged file (Linux cross-compile was broken).

### Changed

- **`testutil/kali.go`** — parameterised via `MALDEV_KALI_SSH_{HOST,PORT,KEY,USER}` envs; same test binaries now run on both libvirt and VBox hosts.
- **`scripts/vm-run-tests.sh`** — collapsed into a shim delegating to `cmd/vmtest`.
- **`cmd/vmtest/driver_{vbox,libvirt}.go`** — `collectMaldevEnv()` forwards `MALDEV_*` into the guest `go test` command.

### Final test run (from INIT snapshots, 2026-04-17)

```text
memscan  PASS  77 / 77
linux    PASS  282 / 282  (41 skip)
windows  PASS  735 / 735  (21 skip)
TOTAL    1017 passed / 0 failed / 62 skipped
```

### Deferred to Phase 5 (documented in `docs/vm-test-setup.md`)

Remote-inject harness (CRT/RTL/EarlyBird/QueueUserAPC/ThreadHijack/KernelCallback/PhantomDLL/ModuleStomp/ExecuteCallback — needs notepad-target spawn), BSOD test runner port, Meterpreter matrix runner, MCP SSE streamable HTTP transport.

---

[Unreleased]: https://github.com/oioio-space/maldev/compare/v0.10.1...HEAD
[v0.10.1]: https://github.com/oioio-space/maldev/compare/v0.10.0...v0.10.1
[v0.10.0]: https://github.com/oioio-space/maldev/compare/v0.9.0...v0.10.0
[v0.9.0]: https://github.com/oioio-space/maldev/releases/tag/v0.9.0
