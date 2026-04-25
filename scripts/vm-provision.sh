#!/usr/bin/env bash
# vm-provision.sh — install missing frameworks/tools inside each test VM and
# snapshot the equipped state as <name>. Idempotent: every check short-circuits
# when the tool is already present.
#
# What gets installed (requires internet inside the VM):
#   Windows VM (win10)
#     - .NET Framework 3.5 (for pe/clr CLR tests)
#     - (UPX 4.x is already present by default, 3.x install path documented
#        but skipped — pe/morph would need a rewrite)
#     - WER LocalDumps (no install; registry keys) so crashing test binaries
#       write a full minidump to C:\Dumps for post-mortem analysis. Debugged
#       EkkoStrategy's SF032 stack-clobbering bug and stays configured for
#       future pool-thread crash investigation.
#   Kali VM (debian13)
#     - postgresql service enabled + started
#     - msfdb init (database.yml for MSF)
#   Linux VM (ubuntu20.04-)
#     - currently nothing; kept as a hook for future additions
#
# After each VM is provisioned successfully, a snapshot is created with the
# name from $SNAPSHOT (default "TOOLS"). Pass --snapshot=NAME to override.
#
# Usage:
#   scripts/vm-provision.sh                   # provision all 3, snapshot TOOLS
#   scripts/vm-provision.sh --skip-snapshot   # provision but don't snapshot
#   scripts/vm-provision.sh --only=windows    # provision just one VM
#
# Notes:
#   - Uses scripts/vm-provision.bat (pushed via scp) + schtasks SYSTEM to
#     bypass Windows UAC (OpenSSH sessions run at medium integrity).
#   - Kali sudo password is hardcoded as "test" — matches the INIT snapshot
#     bootstrap. Override via MALDEV_KALI_SUDO_PASSWORD.

set -euo pipefail
cd "$(dirname "$0")/.."

WIN_IP="${MALDEV_VM_WINDOWS_SSH_HOST:-192.168.122.122}"
LINUX_IP="${MALDEV_VM_LINUX_SSH_HOST:-192.168.122.63}"
KALI_IP="${MALDEV_KALI_SSH_HOST:-192.168.122.246}"
WIN_DOM="${MALDEV_VM_WINDOWS_LIBVIRT_NAME:-win10}"
LINUX_DOM="${MALDEV_VM_LINUX_LIBVIRT_NAME:-ubuntu20.04-}"
KALI_DOM="${MALDEV_KALI_LIBVIRT_NAME:-debian13}"
LIBVIRT_URI="${MALDEV_LIBVIRT_URI:-qemu:///session}"
KALI_PASS="${MALDEV_KALI_SUDO_PASSWORD:-test}"
SNAPSHOT="TOOLS"
SKIP_SNAPSHOT=0
ONLY=""

for arg in "$@"; do
    case "$arg" in
        --skip-snapshot)   SKIP_SNAPSHOT=1 ;;
        --snapshot=*)      SNAPSHOT="${arg#--snapshot=}" ;;
        --only=*)          ONLY="${arg#--only=}" ;;
        *)                 echo "unknown flag: $arg"; exit 2 ;;
    esac
done

log()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
done_msg() { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }

selected() {
    [ -z "$ONLY" ] && return 0
    [ "$ONLY" = "$1" ] && return 0
    return 1
}

vm_running() { LC_ALL=C virsh -c "$LIBVIRT_URI" domstate "$1" 2>/dev/null | grep -q "running"; }
vm_ensure_up() {
    local name="$1"
    if ! vm_running "$name"; then
        log "Starting VM $name"
        virsh -c "$LIBVIRT_URI" start "$name" 2>&1 | tail -3
    fi
}

wait_ssh() {
    local ip="$1" label="$2"
    log "Waiting SSH on $label ($ip)"
    for i in $(seq 1 60); do
        if nc -zw2 "$ip" 22 2>/dev/null; then done_msg "SSH ready ($ip)"; return 0; fi
        sleep 3
    done
    warn "SSH timeout on $label"; return 1
}

snap_create() {
    local name="$1" snap="$2"
    [ "$SKIP_SNAPSHOT" -eq 1 ] && { warn "Skipping snapshot $snap on $name"; return 0; }
    if virsh -c "$LIBVIRT_URI" snapshot-list "$name" 2>/dev/null | grep -q " $snap "; then
        warn "Snapshot $snap already exists on $name — deleting before recreate"
        virsh -c "$LIBVIRT_URI" snapshot-delete "$name" --snapshotname "$snap" 2>&1 | tail -3
    fi
    log "Creating snapshot $snap on $name"
    virsh -c "$LIBVIRT_URI" snapshot-create-as "$name" "$snap" \
        "maldev provisioned: $(date -Iseconds)" 2>&1 | tail -3
    done_msg "Snapshot $snap on $name"
}

# ===========================================================================
# Windows VM — .NET Framework 3.5
# ===========================================================================
provision_windows() {
    local ip="$WIN_IP" key="$HOME/.ssh/vm_windows_key"
    local ssh_base=(-i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes)

    log "Windows: checking .NET Framework 3.5 state"
    local state
    state=$(ssh "${ssh_base[@]}" "test@$ip" \
        'powershell -c "(Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State"' 2>/dev/null | tr -d '\r')
    echo "NetFx3 state: $state"
    if [ "$state" = "Enabled" ]; then
        done_msg ".NET 3.5 already enabled"
    else
        log "Installing .NET 3.5 via DISM (SYSTEM scheduled task)"
        cat > /tmp/maldev-netfx3.bat << 'BAT'
@echo off
dism /online /enable-feature /featurename:NetFx3 /all /quiet /norestart > C:\Users\Public\netfx3.log 2>&1
echo DONE_EXIT=%ERRORLEVEL% >> C:\Users\Public\netfx3.log
BAT
        scp -i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            /tmp/maldev-netfx3.bat "test@$ip:C:/Users/Public/maldev-netfx3.bat" >/dev/null
        ssh "${ssh_base[@]}" "test@$ip" \
            'schtasks /create /tn MaldevProvNetFx3 /tr "C:\Users\Public\maldev-netfx3.bat" /sc once /st 00:00 /ru SYSTEM /f' 2>&1 | tail -3
        ssh "${ssh_base[@]}" "test@$ip" 'schtasks /run /tn MaldevProvNetFx3' 2>&1 | tail -3
        log "Waiting for DISM to finish (typically 3-10 min)"
        local deadline=$((SECONDS + 900))
        while [ $SECONDS -lt $deadline ]; do
            if ssh "${ssh_base[@]}" "test@$ip" \
                'findstr /C:"DONE_EXIT=" C:\Users\Public\netfx3.log' 2>/dev/null | grep -aq "DONE_EXIT="; then
                break
            fi
            sleep 20
        done
        local exit_line
        exit_line=$(ssh "${ssh_base[@]}" "test@$ip" \
            'findstr /C:"DONE_EXIT=" C:\Users\Public\netfx3.log' 2>/dev/null | tr -d '\r')
        echo "DISM result: $exit_line"
        if ! echo "$exit_line" | grep -q "DONE_EXIT=0"; then
            warn ".NET 3.5 install did not report success — check C:\\Users\\Public\\netfx3.log"
        else
            done_msg ".NET 3.5 enabled"
        fi
        ssh "${ssh_base[@]}" "test@$ip" 'schtasks /delete /tn MaldevProvNetFx3 /f' 2>&1 | tail -1
    fi

    # CorRuntimeHost CLSID registration. DISM /enable-feature NetFx3 enables
    # the runtime bits (mscorwks.dll present, csc.exe runs) but skips the
    # legacy COM registration chain — CLSID {CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}
    # remains absent, so CorBindToRuntimeEx returns REGDB_E_CLASSNOTREG and
    # pe/clr tests skip. We mirror the structure of the sibling CLSID
    # {CB2F6723-…} (CorMetaDataDispenser, registered by NetFx3) which points
    # to the same mscoree.dll. Idempotent — `reg import` overwrites.
    # If the Win10 ISO sources/sxs cab is staged on the host, push it +
    # run dism /Add-Package + reboot. This is the most reliable path to
    # finishing the legacy v2 COM activation chain on a TOOLS snapshot.
    # Confirmed 2026-04-25: alone, /Add-Package on Win10 22H2 still leaves
    # CorBindToRuntimeEx returning REGDB_E_CLASSNOTREG; the .NET 3.5 Win7
    # redistributable (dotnetfx35.exe) refuses to install on Win10 silently.
    # The full unblock requires mounting sources/install.wim and pointing
    # DISM at its SxS payload — not yet wired into provisioning.
    local netfx_cab="${MALDEV_NETFX3_CAB:-/run/media/mathieu/CCCOMA_X64FRE_FR-FR_DV9/sources/sxs/microsoft-windows-netfx3-ondemand-package~31bf3856ad364e35~amd64~~.cab}"
    if [ -f "$netfx_cab" ]; then
        log "Windows: pushing NetFx3 OnDemand cab + DISM /Add-Package"
        scp -i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            "$netfx_cab" "test@$ip:C:/Users/Public/netfx3.cab" >/dev/null 2>&1 || \
            warn "scp NetFx3 cab failed — skipping /Add-Package"
        if ssh "${ssh_base[@]}" "test@$ip" \
            'dism /online /Add-Package /PackagePath:"C:\Users\Public\netfx3.cab" /quiet /norestart' >/dev/null 2>&1; then
            done_msg "NetFx3 cab added (reboot may be required for full COM chain)"
        else
            warn "DISM /Add-Package returned non-zero — see netfx-pkg log on VM"
        fi
    else
        warn "NetFx3 cab not staged at $netfx_cab — skip /Add-Package step"
    fi

    log "Windows: registering CorRuntimeHost CLSID"
    cat > /tmp/maldev-corhost.reg << 'REG'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}]
@="Microsoft Common Language Runtime CorRuntimeHost"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}\Implemented Categories]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}\Implemented Categories\{62C8FE65-4EBB-45E7-B440-6E39B2CDBF29}]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}\InprocServer32]
@="C:\\Windows\\System32\\mscoree.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}\InprocServer32\2.0.50727]
"ImplementedInThisVersion"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}\InprocServer32\4.0.30319]
"ImplementedInThisVersion"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}\NotInsertable]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}\ProgID]
@="CLRRuntimeHost"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}\VersionIndependentProgID]
@="CLRRuntimeHost"
REG
    scp -i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        /tmp/maldev-corhost.reg "test@$ip:C:/Users/Public/maldev-corhost.reg" >/dev/null
    ssh "${ssh_base[@]}" "test@$ip" 'reg import C:\Users\Public\maldev-corhost.reg' 2>&1 | tr -d '\r' | tail -2
    if ssh "${ssh_base[@]}" "test@$ip" 'reg query "HKLM\SOFTWARE\Classes\CLSID\{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}\InprocServer32" /ve' >/dev/null 2>&1; then
        done_msg "CorRuntimeHost CLSID registered"
    else
        warn "CorRuntimeHost CLSID registration failed — pe/clr tests will SKIP"
    fi

    log "Windows: configuring WER LocalDumps"
    # LocalDumps requires HKLM edits, which medium-integrity OpenSSH can't do;
    # OpenSSH on this build runs at high integrity (token has S-1-16-12288),
    # so reg.exe directly works. Idempotent — 'reg add /f' overwrites.
    for cmd in \
        'reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v DumpFolder /t REG_EXPAND_SZ /d "C:\Dumps" /f' \
        'reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v DumpType /t REG_DWORD /d 2 /f' \
        'reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v DumpCount /t REG_DWORD /d 10 /f' \
        'reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f' \
        'if not exist C:\Dumps mkdir C:\Dumps'; do
        ssh "${ssh_base[@]}" "test@$ip" "$cmd" > /dev/null 2>&1
    done
    done_msg "WER LocalDumps → C:\\Dumps, DumpType=2 (full)"

    log "Windows: checking UPX"
    if ssh "${ssh_base[@]}" "test@$ip" 'where upx' >/dev/null 2>&1; then
        local upxv
        upxv=$(ssh "${ssh_base[@]}" "test@$ip" 'upx --version 2>&1' | grep -ai '^upx' | head -1 | tr -d '\r')
        done_msg "UPX present: $upxv"
        # pe/morph test requires UPX 3.x — skip is intentional on 4.x.
        echo "$upxv" | grep -qE 'upx 3\.' || \
            warn "UPX is 4.x — pe/morph TestUPXMorphRealBinary stays skipped by design"
    else
        warn "UPX missing — TestUPXMorphRealBinary will skip (manual install only; not provisioned here)"
    fi
}

# ===========================================================================
# Kali VM — postgresql + msfdb
# ===========================================================================
provision_kali() {
    local ip="$KALI_IP" key="$HOME/.ssh/vm_kali_key"
    local ssh_base=(-i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes)

    log "Kali: postgresql + msfdb"
    if [ "$(ssh "${ssh_base[@]}" "test@$ip" 'systemctl is-active postgresql' 2>/dev/null)" = "active" ] \
       && ssh "${ssh_base[@]}" "test@$ip" 'test -f /usr/share/metasploit-framework/config/database.yml' 2>/dev/null; then
        done_msg "postgres active + database.yml present"
        return 0
    fi
    ssh "${ssh_base[@]}" "test@$ip" "echo $KALI_PASS | sudo -S systemctl enable --now postgresql" 2>&1 | tail -3
    ssh "${ssh_base[@]}" "test@$ip" "echo $KALI_PASS | sudo -S msfdb init 2>&1" | tail -5
    done_msg "Kali MSF provisioned"
}

# ===========================================================================
# Linux VM — no-op for now
# ===========================================================================
provision_linux() {
    local ip="$LINUX_IP" key="$HOME/.ssh/vm_linux_key"
    local ssh_base=(-i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes)

    log "Linux: nothing to install (placeholder)"
    # Sanity-check the basics that should already be in INIT.
    ssh "${ssh_base[@]}" "test@$ip" "which go rsync gcc; go version" 2>&1 | tail -3 || true
    done_msg "Linux VM looks provisioned"
}

# ===========================================================================
# Main
# ===========================================================================
if selected windows; then
    vm_ensure_up "$WIN_DOM"
    wait_ssh "$WIN_IP" "$WIN_DOM"
    provision_windows
    snap_create "$WIN_DOM" "$SNAPSHOT"
fi

if selected kali; then
    vm_ensure_up "$KALI_DOM"
    wait_ssh "$KALI_IP" "$KALI_DOM"
    provision_kali
    snap_create "$KALI_DOM" "$SNAPSHOT"
fi

if selected linux; then
    vm_ensure_up "$LINUX_DOM"
    wait_ssh "$LINUX_IP" "$LINUX_DOM"
    provision_linux
    snap_create "$LINUX_DOM" "$SNAPSHOT"
fi

done_msg "Provisioning complete. Snapshots: $SNAPSHOT (override via MALDEV_VM_WINDOWS_SNAPSHOT etc. for vmtest)"
