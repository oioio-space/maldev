# VM Test Setup — Reproducible Bootstrap

> **Scope.** This document covers **bootstrap from zero**: host tools,
> guest OS install, SSH keys, `INIT` snapshot. For per-test-type details
> (injection matrix, Meterpreter, evasion byte-pattern verification, BSOD)
> see [`docs/testing.md`](testing.md). For the cross-platform coverage
> collection workflow (merged report) see
> [`docs/coverage-workflow.md`](coverage-workflow.md).

This guide brings a fresh host (Fedora/libvirt **or** Windows/VirtualBox)
to the state where `./scripts/test-all.sh` runs the full pass/fail matrix:

- **memscan static verification matrix** — 77+ byte-pattern checks
- **Linux VM go test** — intrusive + manual tests enabled
- **Windows VM go test** — intrusive + manual tests enabled

For the merged coverage workflow (same VMs, additionally captures
`cover.out` from each guest and unions profiles into a single report),
run `scripts/full-coverage.sh` after provisioning a `TOOLS` snapshot with
`scripts/vm-provision.sh` — see `docs/coverage-workflow.md`.

The Kali VM (Meterpreter handler) is provisioned similarly but orchestrated
separately via `testutil/kali.go`.

---

## Host requirements

| Host OS | Hypervisor | Tools the host needs |
|--------|-----------|---------------------|
| Fedora / Debian / Ubuntu | libvirt + qemu | `virsh`, `ssh`, `scp`, `rsync`, `sshpass` (for `install-keys.sh`), Go 1.25+ |
| Windows 10/11 | VirtualBox 7+ | VBoxManage on PATH, Git for Windows (Git Bash), Go 1.25+ |

Fedora quick install:
```bash
sudo dnf install -y @virtualization virt-manager virt-install sshpass rsync openssh-clients
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"   # re-login required
```

Windows: download VBox + Go MSI, add `C:\Program Files\Oracle\VirtualBox`
to PATH, open Git Bash.

---

## VM inventory

Three VMs, names committed in `scripts/vm-test/config.yaml` as defaults.
Per-host overrides in `scripts/vm-test/config.local.yaml` (gitignored).

| Role | VirtualBox default name | libvirt default name | Snapshot | User | Purpose |
|------|------------------------|---------------------|----------|------|---------|
| Windows | `Windows10` | `win10` | `INIT` | `test` (admin) | unit + intrusive tests, memscan target |
| Linux | `Ubuntu25.10` | `ubuntu20.04` | `INIT` | `test` | Linux unit tests, procmem/memfd/ptrace |
| Kali | (not managed by vmtest) | `kali` | `INIT` | `test` | MSF msfconsole/msfvenom, Meterpreter end-to-end |

`INIT` is a snapshot taken AFTER provisioning (Go installed, OpenSSH up,
SSH key authorized, firewall opened). Every test run reverts to `INIT`.

---

## One-time bootstrap, from scratch

### 1. Generate host-side SSH keys (one per VM role)

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
ssh-keygen -t ed25519 -f ~/.ssh/vm_windows_key -N '' -C "maldev-vmtest-windows"
ssh-keygen -t ed25519 -f ~/.ssh/vm_linux_key   -N '' -C "maldev-vmtest-linux"
ssh-keygen -t ed25519 -f ~/.ssh/vm_kali_key    -N '' -C "maldev-vmtest-kali"
```

Keys live outside the repo. Never committed.

### 2. Install the guest OSes

- **Linux guest**: Ubuntu 20.04+ or Debian. During install, create local
  user `test` with password `test`, grant sudo. Install can be anything
  (virt-install cloud-init, GNOME Boxes, VirtualBox GUI).
- **Windows guest**: Windows 10/11. During install, create local user
  `test` with password `test`, add to Administrators.
- **Kali guest**: standard Kali install. Create user `test` with password
  `test` (or any pair you pass to `sshpass`).

### 3. Provision each guest (bring it to ready state)

Two paths per guest. Pick one.

#### 3a. Scripted — inside the guest

Copy the bootstrap script into the guest and run it.

- **Linux / Kali guest** — from the host:
  ```bash
  scp scripts/vm-test/bootstrap-linux-guest.sh test@<guest-ip>:/tmp/
  ssh test@<guest-ip> "bash /tmp/bootstrap-linux-guest.sh"
  ```
  The script: installs openssh-server + rsync + curl + Go 1.26 (or
  `GO_VERSION` override), enables sshd at boot, creates `/usr/local/bin/go`
  symlink so non-login SSH sessions see Go.

- **Windows guest** — inside the VM (elevated PowerShell):
  ```powershell
  # Paste the public key and run (one-time):
  iwr -useb http://<host-ip>/bootstrap-windows-guest.ps1 | iex
  # OR copy scripts\vm-test\bootstrap-windows-guest.ps1 into the VM and run:
  .\bootstrap-windows-guest.ps1 -PublicKey "ssh-ed25519 AAAA..."
  ```
  The script: installs OpenSSH Server, starts sshd, opens firewall 22 and
  50300, comments out the `Match Group administrators` block in sshd_config
  (so admin users read `~/.ssh/authorized_keys` normally), installs Go
  into `C:\Go`, creates memscan firewall rule. Pass `-PublicKey` containing
  the content of `~/.ssh/vm_windows_key.pub`.

#### 3b. Manual — if you prefer

See [Manual guest provisioning](#manual-guest-provisioning) at the bottom.

### 4. Push SSH keys into the guests

```bash
# Start each VM and ensure sshd is listening on port 22.
virsh start win10 && virsh start ubuntu20.04 && virsh start kali     # libvirt
# (or use VBoxManage startvm on Windows)

./scripts/vm-test/install-keys.sh linux   # pushes vm_linux_key.pub via ssh-copy-id
./scripts/vm-test/install-keys.sh kali    # same for Kali
# Windows: the bootstrap script already installed the key — skip install-keys.sh.
```

### 5. Create the INIT snapshot on each VM

libvirt:
```bash
for d in win10 ubuntu20.04 kali; do
    virsh snapshot-create-as "$d" --name INIT --description "post-provision ready state"
done
```

VirtualBox:
```bash
for vm in Windows10 Ubuntu25.10 Kali; do
    VBoxManage snapshot "$vm" take INIT --description "post-provision ready state" --live
done
```

### 6. Wire up config.local.yaml (host-side, per-host overrides)

```bash
cp scripts/vm-test/config.local.example.yaml scripts/vm-test/config.local.yaml
# edit: set libvirt_name if your domain names differ, and ssh_key paths.
```

For Kali: its host/user/key come from environment, not YAML.
```bash
cp scripts/vm-test/kali-env.sh.example scripts/vm-test/kali-env.sh
# edit: set MALDEV_KALI_SSH_HOST to `virsh domifaddr kali | awk '/ipv4/...'`
# Then source it from your shell:
echo '. ~/GolandProjects/maldev/scripts/vm-test/kali-env.sh' >> ~/.bashrc
```

### 7. Verify

```bash
./scripts/test-all.sh --only memscan   # static matrix
./scripts/test-all.sh --only linux     # Linux go test ./...
./scripts/test-all.sh --only windows   # Windows go test ./...
./scripts/test-all.sh                  # everything, with a unified report
```

Expected final summary:
```text
  memscan    PASS  total sub-checks: 77 passed / 0 failed (0 fatal row(s))
  linux      PASS  packages: N ok / 0 FAIL (exit=0)
  windows    PASS  packages: N ok / 0 FAIL (exit=0)
overall: PASS
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|--------|-------|-----|
| `virsh list` shows empty | user not in `libvirt` group OR URI mismatch | `sudo usermod -aG libvirt $USER` + re-login; or `virsh -c qemu:///session list` for user-mode VMs (GNOME Boxes default) |
| Windows SSH key-auth refused despite `~/.ssh/authorized_keys` | `Match Group administrators` in sshd_config — admins read `administrators_authorized_keys` | Comment out the Match block (bootstrap script does this) |
| memscan server spawned but `/health` times out | Windows Firewall blocks 50300 | `New-NetFirewallRule -Name memscan-in -Direction Inbound -LocalPort 50300 -Protocol TCP -Action Allow` |
| memscan server dies as soon as SSH session ends | Windows OpenSSH binds children to sshd's JobObject | Orchestrator already uses Task Scheduler (`schtasks /Create /SC ONCE + /Run`) — runs outside the job |
| "Le chemin d'accès spécifié est introuvable" from virsh parsing | French locale | `LC_ALL=C` forced in all scripts (`install-keys.sh`, `driver_libvirt.go`) |
| `go` not in PATH via non-login SSH | default `/etc/profile.d/go.sh` only loads for login shells | Symlink `/usr/local/go/bin/go` → `/usr/local/bin/go` (bootstrap script does this) |
| `ubuntu20.04-` with trailing dash | GNOME Boxes install artifact | Either use the name as-is in `config.local.yaml` or `virsh domrename ubuntu20.04- ubuntu20.04` |
| Kali VM named `debian13` in libvirt | installer chose that name | Use `libvirt_name: debian13` in `kali-env.sh`, or `virsh domrename debian13 kali` |

---

## Manual guest provisioning

If the bootstrap scripts don't fit, here's the minimum each guest needs.

### Linux / Kali guest
```bash
sudo apt update && sudo apt install -y openssh-server rsync curl
sudo systemctl enable --now ssh

curl -LO https://go.dev/dl/go1.26.2.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.26.2.linux-amd64.tar.gz
sudo ln -sf /usr/local/go/bin/go    /usr/local/bin/go
sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
rm go1.26.2.linux-amd64.tar.gz
```

Kali only: `sudo apt install -y metasploit-framework` (usually pre-installed).

### Windows guest (elevated PowerShell)
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
New-NetFirewallRule -Name memscan-in -Direction Inbound -LocalPort 50300 -Protocol TCP -Action Allow
New-NetFirewallRule -Name ssh-in -Direction Inbound -LocalPort 22 -Protocol TCP -Action Allow

# Authorize the host's public key.
$k = 'ssh-ed25519 AAAA... maldev-vmtest-windows'
New-Item -ItemType Directory -Force C:\Users\test\.ssh | Out-Null
Add-Content C:\Users\test\.ssh\authorized_keys $k
icacls C:\Users\test\.ssh\authorized_keys /inheritance:r /grant "test:F" /grant "SYSTEM:F"

# If user 'test' is an admin: comment Match Group administrators block.
$cfg = "$env:ProgramData\ssh\sshd_config"
(Get-Content $cfg) -replace '^(Match Group administrators)','# $1' `
    -replace '^(\s*AuthorizedKeysFile\s+__PROGRAMDATA__)','# $1' |
    Set-Content $cfg -Encoding ASCII
Restart-Service sshd

# Go 1.26.2.
$zip = "$env:TEMP\go.zip"
Invoke-WebRequest https://go.dev/dl/go1.26.2.windows-amd64.zip -OutFile $zip -UseBasicParsing
Expand-Archive $zip -DestinationPath C:\ -Force
[Environment]::SetEnvironmentVariable("Path",
    [Environment]::GetEnvironmentVariable("Path","Machine") + ";C:\Go\bin", "Machine")
Remove-Item $zip
```

Then take a `INIT` snapshot and register the libvirt/VBox name in
`scripts/vm-test/config.local.yaml`.

---

## Future extensions (Phase 5)

Not currently in the matrix, kept in this note so a contributor can add them
without re-deriving the design:

1. **Remote-inject verifs** (~20 additional sub-checks): `CreateRemoteThread`,
   `RtlCreateUserThread`, `EarlyBirdAPC`, `QueueUserAPC`, `ThreadHijack`,
   `KernelCallbackExec`, `PhantomDLLInject`, `ModuleStomp`,
   `ExecuteCallback` {EnumWindows, TimerQueue, CertEnumStore} × 4 callers
   where applicable. Pattern: extend `cmd/memscan-harness/harness_windows.go`
   with a `-target notepad` flag that spawns `notepad.exe`, uses that PID
   for `inject.Config.PID`, then reports both harness PID and `target_pid=<notepad>`.
   The orchestrator attaches to `target_pid` for `/find`. Expected
   "fails" per `docs/testing.md:61-62`: ThreadHijack+Direct/Indirect (RSP
   alignment), CreateFiber (deadlocks Go).

2. **BSOD test** (crashes VM, restores snapshot): reimplement the gitignored
   `scripts/vm-test-bsod.go` using the same vmtest driver. Launch harness
   via scheduled task that calls `bsod.Trigger(nil)`, poll sshd
   disappearance on the VM, then `driver.Restore()`.

3. **Meterpreter matrix** (~21 end-to-end sessions): wrap the
   Meterpreter e2e scenarios from `docs/testing.md:78-108` in the same
   matrix-runner shape as memscan. Each row: spawn MSF handler on Kali
   via `testutil.KaliStartListener`, inject msfvenom shellcode via one
   `Method × Caller`, assert `testutil.KaliCheckSession()` returns true.

4. **MCP SSE streamable HTTP**: the stdio MCP adapter
   (`cmd/memscan-mcp`) already speaks JSON-RPC 2.0. To expose it over
   network for remote Claude Code usage, add `--sse` mode that listens
   HTTP on a port, implementing the MCP SSE transport. ~100 LoC.
