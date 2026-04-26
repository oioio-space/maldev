#!/usr/bin/env bash
# vm-run-tests.sh — shim that delegates to cmd/vmtest (the real orchestrator).
#
# Usage (unchanged from the pre-refactor script):
#   ./scripts/vm-run-tests.sh {windows|windows11|linux|all} [packages] [flags]
#
# Driver is auto-detected (VBoxManage → vbox, else virsh → libvirt).
# Override with MALDEV_VM_DRIVER=vbox|libvirt or `--driver`.
# Per-host config: scripts/vm-test/config.local.yaml (gitignored).

set -euo pipefail
cd "$(dirname "$0")/.."
exec go run ./cmd/vmtest "$@"
