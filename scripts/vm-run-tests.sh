#!/usr/bin/env bash
# vm-run-tests.sh — Run Go tests inside VirtualBox VMs with snapshot isolation
#
# Usage:
#   ./scripts/vm-run-tests.sh windows [packages] [flags]
#   ./scripts/vm-run-tests.sh linux [packages] [flags]
#   ./scripts/vm-run-tests.sh all [packages] [flags]
#
# Examples:
#   ./scripts/vm-run-tests.sh windows "./..." "-v -count=1"
#   ./scripts/vm-run-tests.sh linux "./persistence/..." "-v"
#   ./scripts/vm-run-tests.sh all "./..." "-count=1"

set -euo pipefail

VBOX="C:/Program Files/Oracle/VirtualBox/VBoxManage.exe"
WIN_VM="Windows10"
LIN_VM="Ubuntu25.10"
WIN_SNAPSHOT="INIT"
LIN_SNAPSHOT="INIT"
VM_USER="test"
VM_PASS="test"
PACKAGES="${2:-./...}"
FLAGS="${3:--count=1}"

run_windows() {
    echo "=== Windows VM Tests ==="
    echo "Starting $WIN_VM..."
    "$VBOX" startvm "$WIN_VM" --type headless

    echo "Waiting for Guest Additions (60s)..."
    sleep 60

    echo "Running tests: go test $PACKAGES $FLAGS"
    "$VBOX" guestcontrol "$WIN_VM" run \
        --exe "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
        --username "$VM_USER" --password "$VM_PASS" \
        --wait-stdout --wait-stderr \
        -- powershell.exe -ExecutionPolicy Bypass \
        -File "Z:\\scripts\\vm-test.ps1" \
        -Packages "$PACKAGES" \
        -Flags "$FLAGS"

    local exit_code=$?

    echo "Shutting down $WIN_VM..."
    "$VBOX" controlvm "$WIN_VM" poweroff 2>/dev/null || true
    sleep 3

    echo "Restoring snapshot $WIN_SNAPSHOT..."
    "$VBOX" snapshot "$WIN_VM" restore "$WIN_SNAPSHOT"

    echo "=== Windows: exit code $exit_code ==="
    return $exit_code
}

run_linux() {
    echo "=== Linux VM Tests ==="
    echo "Starting $LIN_VM..."
    "$VBOX" startvm "$LIN_VM" --type headless

    # Add shared folder
    "$VBOX" sharedfolder add "$LIN_VM" --name "maldev" \
        --hostpath "C:\\Users\\m.bachmann\\GolandProjects\\maldev" \
        --automount --transient 2>/dev/null || true

    echo "Waiting for Guest Additions (45s)..."
    sleep 45

    echo "Running tests: go test $PACKAGES $FLAGS"
    "$VBOX" guestcontrol "$LIN_VM" run \
        --exe "/bin/bash" \
        --username "$VM_USER" --password "$VM_PASS" \
        --wait-stdout --wait-stderr \
        -- bash -c "
            cp -r /media/sf_maldev /tmp/maldev 2>/dev/null || cp -r /mnt/maldev /tmp/maldev;
            cd /tmp/maldev;
            go test $PACKAGES $FLAGS 2>&1;
            echo VM_TEST_EXIT_CODE=\$?
        "

    local exit_code=$?

    echo "Shutting down $LIN_VM..."
    "$VBOX" controlvm "$LIN_VM" poweroff 2>/dev/null || true
    sleep 3

    echo "Restoring snapshot $LIN_SNAPSHOT..."
    "$VBOX" snapshot "$LIN_VM" restore "$LIN_SNAPSHOT"

    echo "=== Linux: exit code $exit_code ==="
    return $exit_code
}

case "${1:-all}" in
    windows|win) run_windows ;;
    linux|lin)   run_linux ;;
    all)
        run_windows
        run_linux
        ;;
    *)
        echo "Usage: $0 {windows|linux|all} [packages] [flags]"
        exit 1
        ;;
esac
