#!/usr/bin/env bash
# full-coverage.sh — reproducible end-to-end coverage collection across
# host + Linux VM + Windows VM + Kali VM, with every gate (MALDEV_INTRUSIVE,
# MALDEV_MANUAL, MALDEV_KALI_*) set so gated tests run instead of skipping.
#
# Produces:
#   ignore/coverage/cover-linux-host.out           — host profile
#   ignore/coverage/ubuntu20.04-/{cover.out,test.log} — Linux VM artifacts
#   ignore/coverage/win10/{cover.out,test.log}        — Windows VM artifacts
#   ignore/coverage/cover-merged-full.out          — merged profile
#   ignore/coverage/report-full.md                 — final Markdown report
#
# Idempotent: can be re-run after code changes. VMs are always restored to
# their INIT snapshot when done (no persistent side effects).
#
# Usage:
#   scripts/full-coverage.sh                    # defaults — full run
#   scripts/full-coverage.sh --no-restore       # leave VMs running after
#   scripts/full-coverage.sh --skip-host        # skip host coverage pass
#   scripts/full-coverage.sh --skip-linux-vm    # skip linux VM
#   scripts/full-coverage.sh --skip-windows-vm  # skip windows VM

set -euo pipefail
cd "$(dirname "$0")/.."

# ---------------------------------------------------------------------------
# Config — overridable via env
# ---------------------------------------------------------------------------
WIN_IP="${MALDEV_VM_WINDOWS_SSH_HOST:-192.168.122.122}"
LINUX_IP="${MALDEV_VM_LINUX_SSH_HOST:-192.168.122.63}"
KALI_IP="${MALDEV_KALI_SSH_HOST:-192.168.122.246}"
WIN_DOMAIN="${MALDEV_VM_WINDOWS_LIBVIRT_NAME:-win10}"
LINUX_DOMAIN="${MALDEV_VM_LINUX_LIBVIRT_NAME:-ubuntu20.04-}"
KALI_DOMAIN="${MALDEV_KALI_LIBVIRT_NAME:-debian13}"
LIBVIRT_URI="${MALDEV_LIBVIRT_URI:-qemu:///session}"
COVER_DIR="${MALDEV_COVERAGE_DIR:-ignore/coverage}"

RESTORE=1
SKIP_HOST=0
SKIP_LINUX_VM=0
SKIP_WINDOWS_VM=0
SNAPSHOT="${MALDEV_VM_SNAPSHOT:-INIT}"
for arg in "$@"; do
    case "$arg" in
        --no-restore)      RESTORE=0 ;;
        --skip-host)       SKIP_HOST=1 ;;
        --skip-linux-vm)   SKIP_LINUX_VM=1 ;;
        --skip-windows-vm) SKIP_WINDOWS_VM=1 ;;
        --snapshot=*)      SNAPSHOT="${arg#--snapshot=}" ;;
        *)                 echo "unknown flag: $arg"; exit 2 ;;
    esac
done

# Propagate snapshot to vmtest so it restores to the same one we're pinning.
export MALDEV_VM_WINDOWS_SNAPSHOT="$SNAPSHOT"
export MALDEV_VM_LINUX_SNAPSHOT="$SNAPSHOT"

mkdir -p "$COVER_DIR"
log() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# VM lifecycle helpers
# ---------------------------------------------------------------------------
vm_running() {
    virsh -c "$LIBVIRT_URI" domstate "$1" 2>/dev/null | grep -q "running"
}

vm_ensure_running() {
    local name="$1"
    if vm_running "$name"; then
        log "VM $name already running"
        return 0
    fi
    log "Starting VM $name"
    # Tolerate "already active" — transient state right after snapshot revert
    # can have domstate flip between running/shutoff; virsh-start then races.
    if ! virsh -c "$LIBVIRT_URI" start "$name" 2>&1 | tee /tmp/vmstart.log; then
        if grep -qiE "already active|déjà actif" /tmp/vmstart.log; then
            warn "$name was already running despite domstate check — continuing"
            return 0
        fi
        return 1
    fi
}

vm_wait_ssh() {
    local ip="$1" name="$2"
    log "Waiting for SSH on $name ($ip)"
    for i in $(seq 1 60); do
        if nc -zw2 "$ip" 22 2>/dev/null; then
            echo "SSH reachable at $ip:22 (attempt $i)"
            return 0
        fi
        sleep 3
    done
    warn "SSH never answered on $ip:22 — aborting"
    return 1
}

vm_stop_and_restore() {
    local name="$1" snap="$2"
    [ "$RESTORE" -eq 0 ] && { warn "Leaving $name running (--no-restore)"; return; }
    log "Stopping + restoring $name to $snap"
    virsh -c "$LIBVIRT_URI" destroy "$name" 2>/dev/null || true
    sleep 2
    virsh -c "$LIBVIRT_URI" snapshot-revert "$name" --snapshotname "$snap" --force
}

# ---------------------------------------------------------------------------
# Gate env — exported so every go test call picks them up
# ---------------------------------------------------------------------------
export MALDEV_INTRUSIVE=1
export MALDEV_MANUAL=1
export MALDEV_KALI_SSH_HOST="$KALI_IP"
export MALDEV_KALI_SSH_PORT=22
export MALDEV_KALI_SSH_KEY="$HOME/.ssh/vm_kali_key"
export MALDEV_KALI_USER=test
export MALDEV_KALI_HOST="$KALI_IP"
export MALDEV_VM_WINDOWS_SSH_HOST="$WIN_IP"
export MALDEV_VM_LINUX_SSH_HOST="$LINUX_IP"

# ---------------------------------------------------------------------------
# Phase 1 — bring Kali up so MSF/Meterpreter tests have a target
# ---------------------------------------------------------------------------
if [ "$SKIP_WINDOWS_VM" -eq 0 ] || [ "$SKIP_LINUX_VM" -eq 0 ]; then
    vm_ensure_running "$KALI_DOMAIN"
    vm_wait_ssh "$KALI_IP" "$KALI_DOMAIN" || warn "Kali not reachable — MSF tests will skip"
fi

# ---------------------------------------------------------------------------
# Phase 2 — host coverage
# ---------------------------------------------------------------------------
if [ "$SKIP_HOST" -eq 0 ]; then
    log "Host coverage pass"
    go test -coverprofile="$COVER_DIR/cover-linux-host.out" -covermode=atomic \
        -json ./... > "$COVER_DIR/test-linux-host.json" 2> "$COVER_DIR/test-linux-host.stderr" || \
        warn "Host go test returned non-zero (check $COVER_DIR/test-linux-host.stderr)"
    go tool cover -func="$COVER_DIR/cover-linux-host.out" | tail -1
fi

# ---------------------------------------------------------------------------
# Phase 3 — Linux VM coverage
# ---------------------------------------------------------------------------
if [ "$SKIP_LINUX_VM" -eq 0 ]; then
    log "Linux VM coverage pass"
    # vmtest handles Start/WaitReady/Push/Exec/Fetch/Stop/Restore; pass the
    # VM-side IP through env so domifaddr auto-discovery is bypassed.
    # A failing test returns non-zero — the profile is still useful, so we
    # swallow the exit code and continue to the next phase.
    go run ./cmd/vmtest -report-dir="$COVER_DIR" linux "./..." \
        "-count=1 -v -p 2 -timeout=25m" 2>&1 | \
        tee "$COVER_DIR/vm-linux-full.log" || \
        warn "Linux VM tests returned non-zero (expected when a gated test fails)"
fi

# ---------------------------------------------------------------------------
# Phase 4 — Windows VM coverage (all gates open)
# ---------------------------------------------------------------------------
if [ "$SKIP_WINDOWS_VM" -eq 0 ]; then
    log "Windows VM coverage pass (MALDEV_INTRUSIVE=1, MALDEV_MANUAL=1)"
    go run ./cmd/vmtest -report-dir="$COVER_DIR" windows "./..." \
        "-count=1 -v -p 2 -timeout=30m" 2>&1 | \
        tee "$COVER_DIR/vm-windows-full.log" || \
        warn "Windows VM tests returned non-zero (expected when a gated test fails)"
fi

# ---------------------------------------------------------------------------
# Phase 5 — merge + report
# ---------------------------------------------------------------------------
log "Merging profiles + rendering report"
profiles=()
[ -f "$COVER_DIR/cover-linux-host.out" ]          && profiles+=("$COVER_DIR/cover-linux-host.out")
[ -f "$COVER_DIR/$LINUX_DOMAIN/cover.out" ]       && profiles+=("$COVER_DIR/$LINUX_DOMAIN/cover.out")
[ -f "$COVER_DIR/$WIN_DOMAIN/cover.out" ]         && profiles+=("$COVER_DIR/$WIN_DOMAIN/cover.out")
# clrhost subprocess profile — emitted by testutil.RunCLROperation when
# .NET 3.5 is present. Missing silently if the CLR tests skipped.
[ -f "$COVER_DIR/$WIN_DOMAIN/clrhost-cover.out" ] && profiles+=("$COVER_DIR/$WIN_DOMAIN/clrhost-cover.out")

if [ "${#profiles[@]}" -eq 0 ]; then
    warn "No profiles to merge — aborting"
    exit 1
fi
go run scripts/coverage-merge.go \
    -out "$COVER_DIR/cover-merged-full.out" \
    -report "$COVER_DIR/report-full.md" \
    "${profiles[@]}"

# ---------------------------------------------------------------------------
# Phase 6 — tally (native go test format)
# ---------------------------------------------------------------------------
log "Per-run tallies"
{
    echo "=== maldev full-coverage tallies ==="
    for d in "$COVER_DIR"/cover-linux-host.out; do
        [ -f "$d" ] || continue
        cov=$(go tool cover -func="$d" 2>/dev/null | tail -1 | awk '{print $NF}')
        printf "  %-40s cov=%s (linux host)\n" "${d#$COVER_DIR/}" "$cov"
    done
    for d in "$COVER_DIR/$LINUX_DOMAIN" "$COVER_DIR/$WIN_DOMAIN"; do
        [ -d "$d" ] || continue
        # -a: the Windows test.log has mixed CR/LF/CRLF line endings; without
        # -a grep detects it as binary and returns 0 for every pattern.
        p=$(grep -ac '^--- PASS:' "$d/test.log" 2>/dev/null); p=${p:-0}
        f=$(grep -ac '^--- FAIL:' "$d/test.log" 2>/dev/null); f=${f:-0}
        s=$(grep -ac '^--- SKIP:' "$d/test.log" 2>/dev/null); s=${s:-0}
        cov=$(go tool cover -func="$d/cover.out" 2>/dev/null | tail -1 | awk '{print $NF}')
        printf "  %-40s cov=%s P=%-4s F=%-3s S=%-3s\n" "${d#$COVER_DIR/}" "$cov" "$p" "$f" "$s"
    done
    merged_cov=$(go tool cover -func="$COVER_DIR/cover-merged-full.out" 2>/dev/null | tail -1 | awk '{print $NF}')
    echo
    echo "  ----------------------------------------"
    printf "  %-40s cov=%s (merged)\n" "cover-merged-full.out" "$merged_cov"
} | tee "$COVER_DIR/tallies.txt"

# ---------------------------------------------------------------------------
# Phase 7 — teardown (deferred-ish)
# ---------------------------------------------------------------------------
[ "$SKIP_WINDOWS_VM" -eq 0 ] && vm_stop_and_restore "$WIN_DOMAIN" "$SNAPSHOT"
[ "$SKIP_LINUX_VM" -eq 0 ]   && vm_stop_and_restore "$LINUX_DOMAIN" "$SNAPSHOT"
vm_stop_and_restore "$KALI_DOMAIN" "$SNAPSHOT"

log "DONE — report: $COVER_DIR/report-full.md"
