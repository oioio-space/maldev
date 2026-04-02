#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# maldev test runner — cross-platform (Linux native + Windows via Git Bash)
#
# Detects the platform and runs the appropriate test tiers:
#   Tier 1: Pure Go tests (everywhere)
#   Tier 2: Platform-specific safe tests (everywhere)
#   Tier 3: Intrusive tests (gated by MALDEV_INTRUSIVE=1)
#   Tier 4: Linux tests via Podman (when on Windows)
#
# Usage:
#   ./testutil/run-tests.sh              # Tier 1+2 (safe, default)
#   ./testutil/run-tests.sh --intrusive  # Tier 1+2+3
#   ./testutil/run-tests.sh --all        # Tier 1+2+3+4 (Podman Linux)
#   ./testutil/run-tests.sh --linux      # Tier 4 only (Podman Linux)
#   ./testutil/run-tests.sh --help
#
# Results are saved to testutil/results/<timestamp>-<platform>.log
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────

RESULTS_DIR="testutil/results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
PODMAN=""
MODE="safe"
GO_TEST_TIMEOUT="120s"

# ── Colors ──────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Helpers ─────────────────────────────────────────────────────────

log()  { echo -e "${CYAN}[test]${NC} $*"; }
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }

usage() {
    cat <<'EOF'
maldev test runner

Usage:
  ./testutil/run-tests.sh [OPTIONS]

Options:
  (none)        Run Tier 1+2: pure + platform-safe tests
  --intrusive   Run Tier 1+2+3: + intrusive tests (AMSI, ETW, injection)
  --linux       Run Tier 4 only: Linux tests via Podman container
  --all         Run all tiers (1+2+3+4)
  --help, -h    Show this help

Tiers:
  1  Pure Go tests (crypto, encode, hash, random, pe/parse, inject config)
  2  Platform-safe tests (version, token, process enum, antidebug, antivm)
  3  Intrusive tests (AMSI patch, ETW patch, injection, unhook) — gated
  4  Linux container tests via Podman (ptrace, memfd, procmem, purego)

Results saved to: testutil/results/<timestamp>-<platform>.log

Environment:
  MALDEV_INTRUSIVE=1    Enable intrusive tests (Tier 3)
  MALDEV_MANUAL=1       Enable manual-only tests (requires VM + admin)
  PODMAN_BIN            Override Podman binary path

Examples:
  ./testutil/run-tests.sh                  # Safe tests only
  ./testutil/run-tests.sh --intrusive      # + intrusive (Windows: AMSI, ETW, inject)
  ./testutil/run-tests.sh --linux          # Linux tests in Podman container
  ./testutil/run-tests.sh --all            # Everything
EOF
    exit 0
}

# ── Parse args ──────────────────────────────────────────────────────

for arg in "$@"; do
    case "$arg" in
        --intrusive)  MODE="intrusive" ;;
        --linux)      MODE="linux" ;;
        --all)        MODE="all" ;;
        --help|-h)    usage ;;
        *)            echo "Unknown option: $arg"; usage ;;
    esac
done

# ── Detect Podman ───────────────────────────────────────────────────

detect_podman() {
    # Linux native
    if command -v podman &>/dev/null; then
        PODMAN="podman"
        return 0
    fi
    # Windows — standard install path
    local win_podman="/c/Program Files/RedHat/Podman/podman.exe"
    if [[ -f "$win_podman" ]]; then
        PODMAN="$win_podman"
        return 0
    fi
    # User override
    if [[ -n "${PODMAN_BIN:-}" ]] && [[ -f "$PODMAN_BIN" ]]; then
        PODMAN="$PODMAN_BIN"
        return 0
    fi
    return 1
}

# ── Podman run wrapper (handles Windows WSL vs Linux native) ────────

podman_run() {
    local mount_src
    local extra_args=("$@")

    if [[ "$PLATFORM" == mingw* ]] || [[ "$PLATFORM" == msys* ]] || [[ "$PLATFORM" == cygwin* ]] || [[ "$(uname -o 2>/dev/null)" == "Msys" ]]; then
        # Windows via Git Bash — route through WSL
        local win_path
        win_path=$(pwd -W 2>/dev/null || pwd)
        # Convert C:\Users\... to /mnt/c/Users/...
        mount_src=$(echo "$win_path" | sed 's|^\([A-Za-z]\):|/mnt/\L\1|; s|\\|/|g')

        MSYS_NO_PATHCONV=1 wsl -d podman-machine-default -- podman run --rm \
            --cap-add=SYS_PTRACE \
            --security-opt seccomp=unconfined \
            -e MALDEV_INTRUSIVE=1 \
            -v "${mount_src}:/src" \
            -w /src \
            golang:1.21-bookworm \
            sh -c "${extra_args[*]}"
    else
        # Linux native — podman directly
        "$PODMAN" run --rm \
            --cap-add=SYS_PTRACE \
            --security-opt seccomp=unconfined \
            -e MALDEV_INTRUSIVE=1 \
            -v "$(pwd):/src" \
            -w /src \
            golang:1.21-bookworm \
            sh -c "${extra_args[*]}"
    fi
}

# ── go list excluding ignore/ ───────────────────────────────────────

go_list() {
    go list ./... 2>/dev/null | grep -v '/ignore'
}

# ── Ensure results dir ──────────────────────────────────────────────

mkdir -p "$RESULTS_DIR"

# ── Tier 1+2: Safe tests (native) ──────────────────────────────────

run_safe() {
    local logfile="${RESULTS_DIR}/${TIMESTAMP}-safe-${PLATFORM}.log"
    log "Tier 1+2: Safe tests (pure + platform-specific)"

    go test $(go_list) -count=1 -timeout "$GO_TEST_TIMEOUT" 2>&1 | tee "$logfile"

    local pass_count fail_count
    pass_count=$(grep -c "^ok" "$logfile" || true)
    fail_count=$(grep -c "^FAIL" "$logfile" || true)

    echo ""
    ok "Passed: $pass_count packages"
    if [[ "$fail_count" -gt 0 ]]; then
        fail "Failed: $fail_count packages"
    fi
    log "Results saved to $logfile"
}

# ── Tier 3: Intrusive tests (native) ───────────────────────────────

run_intrusive() {
    local logfile="${RESULTS_DIR}/${TIMESTAMP}-intrusive-${PLATFORM}.log"
    log "Tier 3: Intrusive tests (MALDEV_INTRUSIVE=1)"
    warn "This will patch AMSI/ETW, inject shellcode, and modify memory"

    MALDEV_INTRUSIVE=1 go test $(go_list) -count=1 -timeout "$GO_TEST_TIMEOUT" 2>&1 | tee "$logfile"

    local pass_count fail_count
    pass_count=$(grep -c "^ok" "$logfile" || true)
    fail_count=$(grep -c "^FAIL" "$logfile" || true)

    echo ""
    ok "Passed: $pass_count packages"
    if [[ "$fail_count" -gt 0 ]]; then
        fail "Failed: $fail_count packages"
    fi
    log "Results saved to $logfile"
}

# ── Tier 4: Linux container tests ───────────────────────────────────

run_linux_container() {
    local logfile="${RESULTS_DIR}/${TIMESTAMP}-linux-container.log"
    log "Tier 4: Linux tests via Podman container"

    if ! detect_podman; then
        fail "Podman not found. Install it or set PODMAN_BIN."
        return 1
    fi
    ok "Podman found: $PODMAN"

    # Packages that have Linux-specific code worth testing in a container
    local linux_pkgs=(
        "./crypto/..."
        "./encode/..."
        "./hash/..."
        "./random/..."
        "./inject/..."
        "./evasion/antidebug/..."
        "./evasion/antivm/..."
        "./evasion/timing/..."
        "./process/enum/..."
        "./c2/transport/..."
        "./c2/meterpreter/..."
        "./c2/cert/..."
        "./cleanup/wipe/..."
    )
    local pkgs_str="${linux_pkgs[*]}"

    log "Pulling golang:1.21-bookworm (first run may take a few minutes)..."
    podman_run "go test ${pkgs_str} -count=1 -timeout ${GO_TEST_TIMEOUT}" 2>&1 | tee "$logfile"

    local pass_count fail_count
    pass_count=$(grep -c "^ok" "$logfile" || true)
    fail_count=$(grep -c "^FAIL" "$logfile" || true)

    echo ""
    ok "Passed: $pass_count packages"
    if [[ "$fail_count" -gt 0 ]]; then
        fail "Failed: $fail_count packages"
    fi
    log "Results saved to $logfile"
}

# ── Main ────────────────────────────────────────────────────────────

echo ""
log "═══════════════════════════════════════════════════"
log "  maldev test runner"
log "  Platform: $PLATFORM | Mode: $MODE"
log "  Time: $(date)"
log "═══════════════════════════════════════════════════"
echo ""

case "$MODE" in
    safe)
        run_safe
        ;;
    intrusive)
        run_safe
        echo ""
        run_intrusive
        ;;
    linux)
        run_linux_container
        ;;
    all)
        run_safe
        echo ""
        run_intrusive
        echo ""
        run_linux_container
        ;;
esac

echo ""
log "All results in: $RESULTS_DIR/"
ls -la "$RESULTS_DIR"/${TIMESTAMP}-* 2>/dev/null
echo ""
