#!/usr/bin/env bash
# bootstrap-linux-guest.sh — run INSIDE a fresh Ubuntu/Debian/Kali VM to
# bring it to the ready state expected by vmtest and memscan.
#
# Usage (from the host):
#   scp scripts/vm-test/bootstrap-linux-guest.sh test@<ip>:/tmp/
#   ssh test@<ip> "bash /tmp/bootstrap-linux-guest.sh"
#
# Environment overrides:
#   GO_VERSION   default 1.26.2 — pins the Go tarball to download
#   SSH_USER     default 'test' — the account authorized_keys belongs to
#   PUBLIC_KEY   optional — ssh public key to append to ~/.ssh/authorized_keys
#
# Idempotent: running twice leaves the system in the same state.

set -euo pipefail

GO_VERSION="${GO_VERSION:-1.26.2}"
SSH_USER="${SSH_USER:-test}"
PUBLIC_KEY="${PUBLIC_KEY:-}"

log() { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[bootstrap]\033[0m %s\n' "$*" >&2; }

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
    if ! sudo -n true 2>/dev/null; then
        err "this script needs passwordless sudo or run as root"
        err "hint: echo '$SSH_USER ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/$SSH_USER"
        exit 1
    fi
fi

log "installing openssh-server + rsync + curl"
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq openssh-server rsync curl ca-certificates

log "enabling sshd"
$SUDO systemctl enable --now ssh

if [ -n "$PUBLIC_KEY" ]; then
    SSH_HOME=$(getent passwd "$SSH_USER" | cut -d: -f6)
    log "authorizing key in $SSH_HOME/.ssh/authorized_keys"
    $SUDO -u "$SSH_USER" mkdir -p "$SSH_HOME/.ssh"
    $SUDO -u "$SSH_USER" chmod 700 "$SSH_HOME/.ssh"
    if ! $SUDO grep -qF "$PUBLIC_KEY" "$SSH_HOME/.ssh/authorized_keys" 2>/dev/null; then
        echo "$PUBLIC_KEY" | $SUDO -u "$SSH_USER" tee -a "$SSH_HOME/.ssh/authorized_keys" >/dev/null
    fi
    $SUDO -u "$SSH_USER" chmod 600 "$SSH_HOME/.ssh/authorized_keys"
fi

# Install Go into /usr/local/go with a /usr/local/bin/go symlink so
# non-login SSH sessions (which don't source /etc/profile.d/go.sh) see it.
if [ -x /usr/local/go/bin/go ] && /usr/local/go/bin/go version | grep -q "go${GO_VERSION} "; then
    log "Go ${GO_VERSION} already installed, skipping download"
else
    log "installing Go ${GO_VERSION}"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GOARCH=amd64 ;;
        aarch64) GOARCH=arm64 ;;
        *)       err "unsupported arch: $ARCH"; exit 1 ;;
    esac
    TARBALL="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    cd /tmp
    curl -fsSL -O "https://go.dev/dl/${TARBALL}"
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "$TARBALL"
    rm -f "$TARBALL"
fi

log "creating /usr/local/bin/go symlinks (for non-login sshd sessions)"
$SUDO ln -sf /usr/local/go/bin/go    /usr/local/bin/go
$SUDO ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

# Optional: Metasploit for Kali — detected via /etc/os-release.
if grep -qiE 'kali' /etc/os-release 2>/dev/null; then
    if ! command -v msfvenom >/dev/null; then
        log "installing metasploit-framework (Kali detected)"
        $SUDO apt-get install -y -qq metasploit-framework
    fi
fi

log "verifying"
/usr/local/bin/go version
which rsync ssh
log "done. Reboot is not required."
