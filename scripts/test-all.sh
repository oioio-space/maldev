#!/usr/bin/env bash
# test-all.sh — full-coverage test runner for maldev, with per-test reporting.
#
# Three layers, sequential, with per-test JSON ingested into cmd/test-report:
#   1. memscan static verification matrix  (77+ byte-pattern checks in Windows VM)
#   2. Linux VM   — go test -json ./... with MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1
#   3. Windows VM — go test -json ./... with MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1
#
# Side-effects:
#   - Sources scripts/vm-test/kali-env.sh if present, so MALDEV_KALI_* reach
#     the guest (vmtest driver forwards MALDEV_* via --putenv/env-prefix).
#   - Writes JSON streams to /tmp/maldev-test-*.json for reproducibility.
#   - Writes a final text report to /tmp/maldev-test-report.txt and prints it.
#
# Usage:
#   ./scripts/test-all.sh                   # everything, stop-on-failure
#   ./scripts/test-all.sh --continue        # keep going after a layer fails
#   ./scripts/test-all.sh --only=memscan    # single layer
#   ./scripts/test-all.sh --pkgs=./c2/...   # restrict to a package glob
#
# Exit code: 0 iff every layer passed (zero failed tests across all VMs).

set -uo pipefail
cd "$(dirname "$0")/.."

# Source Kali env so libvirt users don't have to — idempotent; silent if absent.
if [ -f scripts/vm-test/kali-env.sh ]; then
    # shellcheck disable=SC1091
    . scripts/vm-test/kali-env.sh
fi

do_memscan=1
do_linux=1
do_windows=1
stop_on_fail=1
only=""
pkgs="./..."
flags="-json -count=1 -timeout 600s"

for arg in "$@"; do
    case "$arg" in
        --no-memscan)  do_memscan=0 ;;
        --no-linux)    do_linux=0 ;;
        --no-windows)  do_windows=0 ;;
        --only=*)      only="${arg#--only=}" ;;
        --continue)    stop_on_fail=0 ;;
        --pkgs=*)      pkgs="${arg#--pkgs=}" ;;
        --flags=*)     flags="${arg#--flags=}" ;;
        -h|--help)
            sed -n '3,22p' "$0"
            exit 0
            ;;
    esac
done
if [ -n "$only" ]; then
    do_memscan=0; do_linux=0; do_windows=0
    case "$only" in
        memscan) do_memscan=1 ;;
        linux)   do_linux=1 ;;
        windows) do_windows=1 ;;
        *) echo "unknown --only target: $only" >&2; exit 2 ;;
    esac
fi

GREEN=$(printf '\033[32m')
RED=$(printf '\033[31m')
BOLD=$(printf '\033[1m')
RESET=$(printf '\033[0m')

declare -A layer_rc
declare -A layer_line

banner() {
    local title="$1"
    echo
    echo "========================================================================"
    echo "${BOLD}$title${RESET}"
    echo "========================================================================"
}

run_memscan() {
    banner "[memscan] 77-row static verification matrix"
    local log="/tmp/maldev-test-memscan.log"
    go run scripts/vm-test-memscan.go 2>&1 | tee "$log"
    layer_rc[memscan]=${PIPESTATUS[0]}
    layer_line[memscan]=$(grep -oE 'total sub-checks: [0-9]+ passed / [0-9]+ failed \([0-9]+ fatal[^)]*\)' "$log" | tail -1)
    # Leave the Windows VM in its INIT state for the subsequent windows layer.
    # memscan's orchestrator deliberately skips snapshot-revert (server is
    # reused across matrix rows) so we revert here explicitly.
    restore_init_silent win10
}

# restore_init_silent reverts a libvirt domain to its INIT snapshot. Best-
# effort; ignores missing snapshot / offline domain. Forced with --force so
# running VMs are reverted cleanly.
restore_init_silent() {
    local dom="$1"
    if ! command -v virsh >/dev/null; then return; fi
    LC_ALL=C virsh -c qemu:///session domstate "$dom" >/dev/null 2>&1 || return
    LC_ALL=C virsh -c qemu:///session snapshot-revert "$dom" --snapshotname INIT --force >/dev/null 2>&1 || true
    # Small sleep so sshd reaches Listening state before the next layer polls.
    sleep 3
}

run_vm_layer() {
    local name="$1"; shift
    local packages="$1"; shift
    local jsonFlags="$1"; shift
    banner "[$name] go test $packages $jsonFlags (MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1)"
    local json="/tmp/maldev-test-${name}.json"
    local log="/tmp/maldev-test-${name}.log"
    : > "$json"
    : > "$log"
    # Run vmtest; tee JSON to file AND a short progress digest to stdout.
    MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1 \
        ./scripts/vm-run-tests.sh "$name" "$packages" "$jsonFlags" 2>&1 | tee "$log" |
        while IFS= read -r line; do
            # Each stdout line is either JSON (from go test -json) or a wrapper
            # line (vmtest/driver/ssh banners). Route JSON → file, others → stdout
            # for progress visibility.
            case "$line" in
                '{"Time"'*|'{"Action"'*)
                    echo "$line" >> "$json"
                    ;;
                *)
                    # Extract package-completion info as compact progress:
                    if [[ "$line" == '{"Action":"pass","Package":'* ]] || \
                       [[ "$line" == '{"Action":"fail","Package":'* ]]; then
                        echo "$line" >> "$json"
                    else
                        echo "$line"
                    fi
                    ;;
            esac
        done
    # The real go test -json output goes through tee and exits the inner
    # pipe; the whole pipeline's status is its last command (tee) but we
    # want the orchestrator's exit code — get it from the parent's $?.
    layer_rc[$name]=${PIPESTATUS[0]}

    # Also backfill: some JSON may have arrived via the wrapper-line branch
    # (if the first char of a line wasn't `{`). Re-filter from $log.
    grep -E '^\{"(Time|Action)"' "$log" > "$json" 2>/dev/null || true

    local total_tests
    total_tests=$(grep -cE '"Action":"(pass|fail|skip)","Package":"[^"]+","Test":' "$json" 2>/dev/null || echo 0)
    local failed_tests
    failed_tests=$(grep -cE '"Action":"fail","Package":"[^"]+","Test":' "$json" 2>/dev/null || echo 0)
    layer_line[$name]="JSON events: ${total_tests} test-level, ${failed_tests} failed (exit=${layer_rc[$name]})"
}

summary() {
    banner "SUMMARY"
    local overall=0
    for name in memscan linux windows; do
        if [ -z "${layer_rc[$name]+x}" ]; then continue; fi
        local rc=${layer_rc[$name]}
        local mark
        if [ "$rc" -eq 0 ]; then mark="${GREEN}PASS${RESET}"; else mark="${RED}FAIL${RESET}"; overall=$rc; fi
        printf "  %-10s %s  %s\n" "$name" "$mark" "${layer_line[$name]:-}"
    done

    # Run cmd/test-report over the JSON files we produced (linux + windows).
    local rargs=()
    [ -f /tmp/maldev-test-linux.json ]   && [ -s /tmp/maldev-test-linux.json ]   && rargs+=(-in "linux=/tmp/maldev-test-linux.json")
    [ -f /tmp/maldev-test-windows.json ] && [ -s /tmp/maldev-test-windows.json ] && rargs+=(-in "windows=/tmp/maldev-test-windows.json")
    if [ ${#rargs[@]} -gt 0 ]; then
        banner "PER-TEST REPORT (cmd/test-report)"
        go run ./cmd/test-report "${rargs[@]}" -out /tmp/maldev-test-report.txt || true
        cat /tmp/maldev-test-report.txt
        echo
        echo "full report saved to /tmp/maldev-test-report.txt"
    fi
    echo
    if [ "$overall" -eq 0 ]; then
        echo "${GREEN}${BOLD}overall: PASS${RESET}"
    else
        echo "${RED}${BOLD}overall: FAIL (at least one layer had failures — see report above)${RESET}"
    fi
}

# -- execute layers --

if [ "$do_memscan" -eq 1 ]; then
    run_memscan
    if [ "${layer_rc[memscan]}" -ne 0 ] && [ "$stop_on_fail" -eq 1 ]; then
        summary; exit "${layer_rc[memscan]}"
    fi
fi

if [ "$do_linux" -eq 1 ]; then
    run_vm_layer linux "$pkgs" "$flags"
    if [ "${layer_rc[linux]}" -ne 0 ] && [ "$stop_on_fail" -eq 1 ]; then
        summary; exit "${layer_rc[linux]}"
    fi
fi

if [ "$do_windows" -eq 1 ]; then
    run_vm_layer windows "$pkgs" "$flags"
    if [ "${layer_rc[windows]}" -ne 0 ] && [ "$stop_on_fail" -eq 1 ]; then
        summary; exit "${layer_rc[windows]}"
    fi
fi

summary

# Exit non-zero if any layer failed.
for name in memscan linux windows; do
    if [ -n "${layer_rc[$name]+x}" ] && [ "${layer_rc[$name]}" -ne 0 ]; then
        exit "${layer_rc[$name]}"
    fi
done
exit 0
