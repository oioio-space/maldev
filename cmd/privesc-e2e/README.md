# cmd/privesc-e2e

End-to-end proof of the maldev DLL-hijack privesc chain.

## What it does

Runs from a non-admin shell on the Win10 target. Packs an embedded
probe EXE into a converted DLL via `packer.PackBinary{ConvertEXEtoDLL:
true}`, plants it where a SYSTEM-context scheduled task expects to
find a DLL, triggers the task, and verifies the probe wrote its
elevated `whoami` output to a marker file.

## Layout

| Path | Role |
|---|---|
| `main.go` | Orchestrator (runs as `lowuser`) |
| `probe/probe.c` | Tiny `-nostdlib` C EXE — kernel32-only, writes whoami marker, sleeps. Embedded into orchestrator via `//go:embed probe/probe.exe`. |
| `probe/main.go` | Original Go probe — **does NOT survive** thread-injection by Mode 8 stub (Go runtime requires being the process entry point). Kept as reference; to be revived once we crack the runtime-init issue. |
| `victim/main.go` | DELIBERATELY VULNERABLE — `LoadLibrary("hijackme.dll")`. Deployed by VM provisioning at `C:\Vulnerable\victim.exe`, run as SYSTEM by the scheduled task. |
| `fakelib/fakelib.go` | Real Go-built `c-shared` DLL with three named exports. Embedded into orchestrator via `//go:embed fakelib/fakelib.dll` for Mode 10 path. |

## Build

The orchestrator `//go:embed`s two binaries: `probe/probe.exe`
(C-built) and `fakelib/fakelib.dll` (Go cgo c-shared). Both must
exist on disk before `go build ./cmd/privesc-e2e` succeeds. The
driver `scripts/vm-privesc-e2e.sh` does this in order:

```bash
# 1. probe (C, mingw)
x86_64-w64-mingw32-gcc -nostdlib -e main \
  -o cmd/privesc-e2e/probe/probe.exe \
  cmd/privesc-e2e/probe/probe.c -lkernel32

# 2. fakelib (Go cgo c-shared) — GOTMPDIR avoids host Defender
GOTMPDIR=$(pwd)/ignore/gotmp CGO_ENABLED=1 \
  GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
  go build -buildmode=c-shared \
  -o cmd/privesc-e2e/fakelib/fakelib.dll ./cmd/privesc-e2e/fakelib

# 3. orchestrator (embeds both)
GOOS=windows GOARCH=amd64 go build -o privesc-e2e.exe ./cmd/privesc-e2e

# 4. victim (deployed on VM by provisioning script)
GOOS=windows GOARCH=amd64 go build -o victim.exe ./cmd/privesc-e2e/victim
```

Both `probe.exe` and `fakelib.dll` are gitignored — rebuild from
source on each run.

## Environment setup — full reproducible procedure

Prerequisites:
- VirtualBox 7.x with a Windows 10 x64 VM named `Windows10` (or
  override via `MALDEV_VM_WINDOWS_VBOX_NAME` in
  `scripts/vm-test/config.local.yaml`).
- An admin SSH account on the VM (default `test` / `test`,
  authenticated via SSH key — see step 2 below).
- A `INIT` snapshot of the VM with OpenSSH-server already enabled
  and the host's SSH public key already in `C:\ProgramData\ssh\administrators_authorized_keys`. The provisioning step below
  layers `lowuser` + victim + scheduled task on top of `INIT`
  every run.
- mingw-w64 on the host (`/c/msys64/mingw64/bin/x86_64-w64-mingw32-gcc`)
  for the C probe + Go cgo c-shared fakelib.
- Go ≥ 1.22 on the host with `GOOS=windows GOARCH=amd64` cross-compile
  working.

### 1. One-time host setup

```bash
# Verify dependencies (each command should print a version).
which x86_64-w64-mingw32-gcc
which go
which VBoxManage    # or set MALDEV_VBOX_EXE to its absolute path

# SSH key for the Win10 admin user — same key the standard maldev
# vmtest harness uses, so other tests stay reachable.
ls ~/.ssh/vm_windows_key ~/.ssh/vm_windows_key.pub
# If missing, generate with `ssh-keygen -t ed25519 -f ~/.ssh/vm_windows_key`
# then install vm_windows_key.pub into the VM (one-time, manually):
#   C:\ProgramData\ssh\administrators_authorized_keys
# Confirm reachability:
ssh -i ~/.ssh/vm_windows_key test@192.168.56.102 'whoami'
# Expected output: DESKTOP-<name>\test
```

### 2. One-time VM setup (snapshot `INIT`)

Inside the VM, as an admin user:
- Install OpenSSH server (`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`),
  set `Set-Service sshd -StartupType Automatic`, `Start-Service sshd`.
- Drop your host SSH public key into `C:\ProgramData\ssh\administrators_authorized_keys`,
  then chmod the file so only SYSTEM + Administrators have access
  (`icacls administrators_authorized_keys /inheritance:r /grant SYSTEM:F /grant Administrators:F`).
- Verify `whoami /priv` includes `SeBatchLogonRight` for the
  admin (the runner harness needs it).
- Power off cleanly, then create the snapshot:

```bash
VBoxManage snapshot Windows10 take INIT --pause
```

That's the snapshot the driver restores every run.

### 3. Per-run setup (driver does this for you)

The driver script (`scripts/vm-privesc-e2e.sh`) is idempotent and
re-creates everything inside the VM from scratch on every
invocation:

| Step | What | Where |
|---|---|---|
| 1. Snapshot restore | `VBoxManage snapshot Windows10 restore INIT` | host |
| 2. SSH wait | up to 180 s, polls every 2 s | host |
| 3. Build artefacts | probe.exe + fakelib.dll + privesc-e2e.exe + victim.exe | host |
| 4. SCP artefacts | to `C:\Users\test\` on the VM | host -> VM |
| 5. `provision-lowuser.ps1` | creates `lowuser`, grants `SeBatchLogonRight`, makes `C:\Users\Public\maldev\` writable, force-sets the password via `net user` so schtasks /RP accepts it later | VM admin |
| 6. `provision-privesc.ps1` | creates `C:\Vulnerable\` writable by `lowuser`, deploys `victim.exe`, registers `MaldevHijackVictim` scheduled task (SYSTEM, auto-fires every minute), opens the marker dir to Everyone (SID `S-1-1-0`, locale-safe) | VM admin |
| 7. Run orchestrator AS lowuser | via `run-as-lowuser.ps1` harness which wraps `schtasks /Create + /Run + poll` | VM admin -> lowuser context |
| 8. Fetch marker + victim.log | scp back to `ignore/privesc-e2e/` | host |
| 9. Verdict | STRONG if marker shows SYSTEM; ADEQUATE if victim.log shows `LoadLibrary succeeded` post-plant | host |
| 10. Teardown | snapshot restore to `INIT` (unless `-k` passed) | host |

### 4. Invocation

```bash
# Mode 8 (ConvertEXEtoDLL): minimal converted-DLL chain
bash scripts/vm-privesc-e2e.sh -m 8

# Mode 10 (PackProxyDLL fused): live-discovered target DLL + proxy
bash scripts/vm-privesc-e2e.sh -m 10

# Debug: keep the VM running on failure for SSH inspection
bash scripts/vm-privesc-e2e.sh -m 8 -k
# Then: ssh -i ~/.ssh/vm_windows_key test@192.168.56.102

# Custom lowuser password (avoid '!' '%' '"' '^' — they break the
# bash->ssh->cmd->schtasks /RP quoting chain)
bash scripts/vm-privesc-e2e.sh -m 8 -p 'OtherSafePassword'
```

### 5. Known gotchas during environment setup

| Symptom | Cause | Fix |
|---|---|---|
| `SSH never came up after 180s` | missing `-i ~/.ssh/vm_windows_key` | confirm key file exists and is in driver's `SSH_OPTS` |
| `Impossible de terminer l'op�ration, car le fichier contient un virus` | Defender flagged a provisioning script (AMSI signature) | switch the script to registry-direct ops or rely on orchestrator's `evasion/preset.Stealth` — see `docs/refactor-2026-doc/privesc-e2e-lessons-2026-05-12.md` |
| `Le mappage entre les noms de compte et les ID de s�curit� n'a pas �t� effectu�` (icacls Everyone) | French Windows locale | use SID `*S-1-1-0` not the name `Everyone` |
| `Le nom d'utilisateur ou le mot de passe est incorrect` (schtasks /RP) | password contains `!` or other cmd-special chars | use only `[A-Za-z0-9]` in `-p` argument |
| `###RC=1` with empty out.txt AS lowuser | `Set-LocalUser` SAM password representation differs from what schtasks expects | provisioning script now also calls `net user $UserName $Password` — verify `b6d26c8` is in HEAD |
| GUI VM but `headless` boot loops | INIT snapshot was taken with desktop session active | re-take snapshot with `VBoxManage startvm Windows10 --type headless` and wait for SSH before snapshotting |

### 6. Where everything lives after a successful run

| Path | Content |
|---|---|
| `C:\Vulnerable\hijackme.dll` | the packed DLL planted by `lowuser` |
| `C:\Vulnerable\fakelib.dll` (Mode 10 only) | the real Go DLL whose exports we mirror |
| `C:\ProgramData\maldev-marker\whoami.txt` | probe payload's whoami output (the STRONG-proof artefact) |
| `C:\ProgramData\maldev-marker\victim.log` | victim.exe LoadLibrary outcomes per minute-trigger fire |
| `C:\ProgramData\maldev-marker\probe-*.txt` | probe breadcrumbs (helpful when the chain partially fires) |
| host `ignore/privesc-e2e/whoami.txt` | fetched marker (STRONG proof if it shows SYSTEM) |
| host `ignore/privesc-e2e/victim.log` | fetched log (ADEQUATE proof if it shows LoadLibrary success) |

## Run

```pwsh
# from lowuser shell on the VM (after driver provisioning, or manually)
privesc-e2e.exe -mode 8
```

Exit 0 = SUCCESS (marker shows SYSTEM or another principal).
Exit 1 = FAIL with diagnostics.

The orchestrator's available flags:

```
-mode int        packer mode: 8 (ConvertEXEtoDLL, minimal) or 10 (PackProxyDLL fused) (default 8)
-discover        use recon/dllhijack to scan and pick the highest-ranked Writable target
-dll string      where to plant the hijack DLL (default "C:\Vulnerable\hijackme.dll")
-task string     scheduled task to trigger (default "MaldevHijackVictim")
-marker string   where the probe will write whoami output (default "C:\ProgramData\maldev-marker\whoami.txt")
-no-trigger      plant the DLL but do not /Run the task -- wait for natural trigger
-compress        LZ4-compress the payload (default true)
-antidebug       AntiDebug PEB+RDTSC check at DllMain entry (default true)
-randomize       Phase 2 randomisation suite (default true)
-rounds int      stage1 SGN rounds (default 3)
```
