#!/usr/bin/env bash
# install-keys.sh — push the vmtest public keys into libvirt guests.
#
# Prereq: VM is running, sshd up, password auth enabled for user 'test'
# with password 'test' (or supply via sshpass / env). For Windows guests,
# install OpenSSH Server first (Settings > Apps > Optional features, or
# `Add-WindowsCapability -Online -Name OpenSSH.Server`) and create
# C:\Users\test\.ssh\authorized_keys manually — ssh-copy-id doesn't cover
# the Windows authorized_keys permission dance.
#
# Usage:
#   ./scripts/vm-test/install-keys.sh           # all known VMs
#   ./scripts/vm-test/install-keys.sh linux     # one VM
#
# Edit the VM_MAP below if your libvirt domain names differ.

set -euo pipefail

# Force English locale — virsh output strings (domstate, etc.) are parsed
# below and the French translations break substring matches.
export LC_ALL=C

declare -A VM_MAP=(
  [linux]="ubuntu20.04-"
  [kali]="debian13"   # the Kali VM is registered under libvirt name 'debian13'
  # windows handled separately — ssh-copy-id on Windows has trust issues.
)

SSH_USER="${SSH_USER:-test}"

resolve_ip() {
    local domain="$1"
    for src in lease agent arp; do
        ip=$(virsh domifaddr "$domain" --source "$src" 2>/dev/null \
             | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -1)
        if [ -n "$ip" ]; then
            echo "$ip"; return 0
        fi
    done
    return 1
}

install_one() {
    local name="$1"
    local domain="${VM_MAP[$name]:-}"
    if [ -z "$domain" ]; then
        echo "unknown VM $name (known: ${!VM_MAP[*]})" >&2
        return 1
    fi
    if ! virsh dominfo "$domain" >/dev/null 2>&1; then
        echo "SKIP $name: libvirt domain '$domain' not defined" >&2
        return 0
    fi
    state=$(virsh domstate "$domain" 2>/dev/null | tr -d ' \n')
    if [ "$state" != "running" ]; then
        echo "SKIP $name: domain '$domain' is $state (start it first)" >&2
        return 0
    fi
    ip=$(resolve_ip "$domain" || true)
    if [ -z "$ip" ]; then
        echo "SKIP $name: no IPv4 found via virsh domifaddr" >&2
        return 0
    fi
    echo "=> $name ($domain) at $ip"
    ssh-copy-id -f -i "$HOME/.ssh/vm_${name}_key.pub" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "${SSH_USER}@${ip}"
}

if [ $# -eq 0 ]; then
    for n in "${!VM_MAP[@]}"; do install_one "$n"; done
else
    for n in "$@"; do install_one "$n"; done
fi
