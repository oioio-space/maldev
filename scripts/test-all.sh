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

set -Euo pipefail
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

### MSF handler auto-provision ###############################################

# kali_ssh runs a command on the Kali VM. Silent failure if kali-env.sh
# isn't sourced or the host is unreachable.
kali_ssh() {
    if [ -z "${MALDEV_KALI_SSH_HOST:-}" ] || [ -z "${MALDEV_KALI_SSH_KEY:-}" ]; then
        return 1
    fi
    ssh -i "$MALDEV_KALI_SSH_KEY" -p "${MALDEV_KALI_SSH_PORT:-22}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=5 \
        "${MALDEV_KALI_USER:-test}@$MALDEV_KALI_SSH_HOST" "$@"
}

# start_msf_handler boots a multi/handler on Kali for the given platform's
# meterpreter reverse_tcp payload, listening on 4444. Blocks until the port
# is reachable (≤30 s). Leaves MSF running in the background via the
# sleep-3600 trick (see docs/testing.md:99-103).
start_msf_handler() {
    local platform="$1"
    local payload
    case "$platform" in
        linux)   payload="linux/x64/meterpreter/reverse_tcp" ;;
        windows) payload="windows/x64/meterpreter/reverse_tcp" ;;
        *) return 0 ;;
    esac
    if ! kali_ssh "true" 2>/dev/null; then
        echo "[msf] Kali not reachable — meterpreter tests will skip"
        return 0
    fi
    echo "[msf] starting $payload handler on $MALDEV_KALI_SSH_HOST:4444"
    # Kill any leftover handler first (idempotent).
    kali_ssh "pkill -f 'ruby.*msf' 2>/dev/null ; rm -f /tmp/msf.log" || true
    kali_ssh "nohup msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD $payload; set LHOST 0.0.0.0; set LPORT 4444; set ExitOnSession false; exploit -j -z; sleep 3600' > /tmp/msf.log 2>&1 &" || true
    # Wait for the listener socket to be up on Kali (0.0.0.0:4444).
    local deadline=$(( $(date +%s) + 30 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if nc -zv -w 2 "$MALDEV_KALI_SSH_HOST" 4444 >/dev/null 2>&1; then
            echo "[msf] handler listening on $MALDEV_KALI_SSH_HOST:4444"
            return 0
        fi
        sleep 1
    done
    echo "[msf] handler failed to start within 30s — meterpreter tests will likely skip"
}

stop_msf_handler() {
    if [ -z "${MALDEV_KALI_SSH_HOST:-}" ]; then return 0; fi
    kali_ssh "pkill -f 'ruby.*msf' 2>/dev/null ; true" 2>/dev/null || true
}

### Kali SSH key propagation into the guest ##################################
# Meterpreter tests that need `testutil.KaliSSH` (msfvenom, session check)
# require the guest to SSH into Kali. We push the host-owned key into the
# guest at a known path and override MALDEV_KALI_SSH_KEY for that layer only.

# push_kali_key_linux scp's the host's Kali key into the Ubuntu guest.
# Returns the guest-side path via echo.
push_kali_key_linux() {
    local guest_host="$1"   # linux guest IP (auto-discovered via virsh)
    local guest_user="${2:-test}"
    local dst="/home/$guest_user/.ssh/vm_kali_key"
    scp -i ~/.ssh/vm_linux_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=5 \
        "$MALDEV_KALI_SSH_KEY" "$guest_user@$guest_host:$dst" >/dev/null 2>&1 || return 1
    ssh -i ~/.ssh/vm_linux_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes "$guest_user@$guest_host" "chmod 600 $dst" >/dev/null 2>&1
    echo "$dst"
}

# push_kali_key_windows scp's the host's Kali key into the Windows guest
# with strict NTFS ACLs (OpenSSH key-file permission check). Returns the
# guest-side path (forward-slash form, for Go/ssh compatibility).
push_kali_key_windows() {
    local guest_host="$1"
    local guest_user="${2:-test}"
    # Use /Users/test/.ssh/vm_kali_key — same convention as the Linux host
    # key, placed where OpenSSH.exe client looks by default.
    scp -i ~/.ssh/vm_windows_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=5 \
        "$MALDEV_KALI_SSH_KEY" "$guest_user@$guest_host:/Users/$guest_user/.ssh/vm_kali_key" >/dev/null 2>&1 || return 1
    # Strict ACLs — OpenSSH refuses to use keys with group/everyone read.
    ssh -i ~/.ssh/vm_windows_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes "$guest_user@$guest_host" \
        "icacls C:\\Users\\$guest_user\\.ssh\\vm_kali_key /inheritance:r /grant ${guest_user}:F /grant SYSTEM:F" >/dev/null 2>&1
    echo "C:\\Users\\$guest_user\\.ssh\\vm_kali_key"
}

# resolve_vm_ip returns the first IPv4 of a libvirt domain (ARP → lease → agent).
resolve_vm_ip() {
    local dom="$1"
    for src in arp lease agent; do
        local out
        out=$(LC_ALL=C virsh -c qemu:///session domifaddr "$dom" --source "$src" 2>/dev/null \
              | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -1)
        if [ -n "$out" ]; then
            echo "$out"
            return 0
        fi
    done
    return 1
}

run_vm_layer() {
    local name="$1"; shift
    local packages="$1"; shift
    local jsonFlags="$1"; shift
    banner "[$name] go test $packages $jsonFlags (MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1)"
    # Spin up a per-platform MSF handler so TestMeterpreterRealSession{,Linux}
    # runs for real instead of skipping on "no listener".
    start_msf_handler "$name"
    trap stop_msf_handler EXIT

    # Provision the Kali SSH key into the guest so tests that use
    # testutil.KaliSSH (msfvenom, session check) actually reach Kali.
    # The per-layer MALDEV_KALI_SSH_KEY_GUEST env overrides the host-side
    # MALDEV_KALI_SSH_KEY when vmtest forwards env into the guest. Nothing
    # persisted in INIT snapshots.
    local guest_ip=""
    local kali_key_guest=""
    local dom
    case "$name" in
        linux)   dom="ubuntu20.04-" ;;
        windows) dom="win10" ;;
    esac
    if [ -n "$dom" ] && [ -n "${MALDEV_KALI_SSH_KEY:-}" ]; then
        guest_ip=$(resolve_vm_ip "$dom")
        if [ -n "$guest_ip" ]; then
            if [ "$name" = "windows" ]; then
                kali_key_guest=$(push_kali_key_windows "$guest_ip" 2>/dev/null || true)
            else
                kali_key_guest=$(push_kali_key_linux "$guest_ip" 2>/dev/null || true)
            fi
            if [ -n "$kali_key_guest" ]; then
                echo "[kali-key] pushed to $name guest at $kali_key_guest"
            fi
        fi
    fi

    local json="/tmp/maldev-test-${name}.json"
    local log="/tmp/maldev-test-${name}.log"
    : > "$json"
    : > "$log"
    # Run vmtest; tee JSON to file AND a short progress digest to stdout.
    # MALDEV_KALI_SSH_KEY is REPLACED with the guest-side path so the test
    # inside the guest opens /Users/test/.ssh/vm_kali_key (Win) or
    # /home/test/.ssh/vm_kali_key (Lin) — not the Fedora-host path.
    MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1 \
    MALDEV_KALI_SSH_KEY="${kali_key_guest:-$MALDEV_KALI_SSH_KEY}" \
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
    # Tear down the per-platform handler so the next layer starts clean.
    stop_msf_handler
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
