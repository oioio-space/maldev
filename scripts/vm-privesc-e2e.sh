#!/usr/bin/env bash
# vm-privesc-e2e.sh — drives the maldev DLL-hijack privesc E2E proof.
#
#  1. Restore Windows10 VM to its INIT snapshot.
#  2. Build (host): probe.exe, victim.exe, privesc-e2e.exe (Windows x64).
#  3. SCP all three to the admin `test` user on the VM.
#  4. Provision: provision-lowuser.ps1 (lowuser account, SeBatchLogonRight)
#     + provision-privesc.ps1 (C:\Vulnerable, victim.exe, SYSTEM scheduled
#     task with lowuser /Run ACL, marker dir).
#  5. Run privesc-e2e.exe AS lowuser via run-as-lowuser.ps1 — orchestrator
#     packs probe LIVE on the VM, plants hijackme.dll, triggers the SYSTEM
#     task, polls marker, prints SUCCESS/FAIL.
#  6. Fetch the marker + victim log back to the host for the verdict.
#
# Args: -m {8|10}  pack mode (default: 8)
#       -p P       low-user password (default: MaldevLow42!)
#
# Exits 0 on SUCCESS (marker shows SYSTEM identity), 1 otherwise.
set -uo pipefail
# Force line buffering on every shell output so background-launchers
# and tail-monitors can see progress in real-time (default block
# buffering hides output until file close).
exec > >(stdbuf -oL -eL cat) 2>&1

MODE=8
LOWPASS='MaldevLow42!'
KEEP_VM=0
while getopts "m:p:k" opt; do
  case $opt in
    m) MODE="$OPTARG" ;;
    p) LOWPASS="$OPTARG" ;;
    k) KEEP_VM=1 ;;
    *) echo "usage: $0 [-m {8|10}] [-p password] [-k keep-vm-on-fail]" >&2; exit 2 ;;
  esac
done

VBOX="${MALDEV_VBOX_EXE:-/c/Program Files/Oracle/VirtualBox/VBoxManage.exe}"
VM_NAME='Windows10'
SNAPSHOT='INIT'
SSH_USER='test'
LOWUSER='lowuser'
HOST_IP='192.168.56.102'
SSH_KEY="${MALDEV_VM_WINDOWS_SSH_KEY:-$HOME/.ssh/vm_windows_key}"
[ -f "$SSH_KEY" ] || { echo "missing SSH key: $SSH_KEY" >&2; exit 1; }
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes)

log() { printf '\033[36m[%s] %s\033[0m\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '\033[31m[%s] FAIL: %s\033[0m\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

teardown() {
  if [ "$KEEP_VM" = 1 ]; then
    log "KEEP_VM=1 — leaving VM running for debug (ssh -i $SSH_KEY ${SSH_USER}@${HOST_IP})"
    return
  fi
  log "tearing down VM"
  "$VBOX" controlvm "$VM_NAME" poweroff &>/dev/null
  sleep 3
  "$VBOX" snapshot "$VM_NAME" restore "$SNAPSHOT" &>/dev/null
}
trap teardown EXIT

# 1. Snapshot restore
log "restoring snapshot $SNAPSHOT"
"$VBOX" controlvm "$VM_NAME" poweroff &>/dev/null || true
sleep 3
"$VBOX" snapshot "$VM_NAME" restore "$SNAPSHOT" &>/dev/null || fail "snapshot restore"
"$VBOX" startvm "$VM_NAME" --type headless &>/dev/null || fail "startvm"

# 2. Wait for SSH — print every 5 attempts so the run never goes
#    silent for more than ~10s during the boot window.
log "waiting for SSH on $HOST_IP (up to 180s)"
ssh_up=0
for i in $(seq 1 90); do
  if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=2 -o BatchMode=yes \
       "${SSH_USER}@${HOST_IP}" "echo ok" &>/dev/null; then
    log "SSH up after ~$((i*2))s"
    ssh_up=1; break
  fi
  if (( i % 5 == 0 )); then
    log "  ...still waiting (attempt $i/90)"
  fi
  sleep 2
done
[ "$ssh_up" = 1 ] || fail "SSH never came up after 180s"

# 3. Build host-side
cd "$(dirname "$0")/.."
log "building probe.exe (mingw -nostdlib) + victim.exe + privesc-e2e.exe (windows/amd64)"
x86_64-w64-mingw32-gcc -nostdlib -e main \
    -o cmd/privesc-e2e/probe/probe.exe \
    cmd/privesc-e2e/probe/probe.c -lkernel32 || fail "build probe (mingw)"
GOOS=windows GOARCH=amd64 go build -o /tmp/victim.exe       ./cmd/privesc-e2e/victim     || fail "build victim"
GOOS=windows GOARCH=amd64 go build -o /tmp/privesc-e2e.exe  ./cmd/privesc-e2e            || fail "build orchestrator"

# 4. Push artifacts + provisioning scripts
log "uploading artifacts to ${SSH_USER}@${HOST_IP}"
scp "${SSH_OPTS[@]}" \
    /tmp/victim.exe \
    /tmp/privesc-e2e.exe \
    scripts/vm-test/provision-lowuser.ps1 \
    scripts/vm-test/provision-privesc.ps1 \
    scripts/vm-test/run-as-lowuser.ps1 \
    "${SSH_USER}@${HOST_IP}:C:/Users/${SSH_USER}/" &>/dev/null || fail "scp upload"

# 5. Provision lowuser
log "provisioning lowuser account"
ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST_IP}" \
  "powershell -ExecutionPolicy Bypass -File C:\\Users\\${SSH_USER}\\provision-lowuser.ps1 -Password '${LOWPASS}'" \
  || fail "provision-lowuser"

# 6. Provision privesc target (victim + SYSTEM task)
log "provisioning victim.exe + SYSTEM scheduled task"
ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST_IP}" \
  "powershell -ExecutionPolicy Bypass -File C:\\Users\\${SSH_USER}\\provision-privesc.ps1 -VictimSource C:\\Users\\${SSH_USER}\\victim.exe" \
  || fail "provision-privesc"

# 7. Drop privesc-e2e.exe somewhere lowuser can read (Public is universally
#    readable). The orchestrator will then write hijackme.dll to C:\Vulnerable\
#    which is lowuser-writable.
log "moving privesc-e2e.exe → C:\\Users\\Public\\maldev"
ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST_IP}" \
  "powershell -Command \"Copy-Item C:\\Users\\${SSH_USER}\\privesc-e2e.exe C:\\Users\\Public\\maldev\\privesc-e2e.exe -Force\"" \
  || fail "copy orchestrator"

# 8. Tail victim.log + marker dir over SSH in the background so the
#    operator sees real-time evidence of the chain firing (or not).
log "starting background tail of C:\\ProgramData\\maldev-marker\\ (real-time VM activity)"
ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST_IP}" \
  "powershell -Command \"while(\$true){Get-ChildItem C:\\ProgramData\\maldev-marker\\ -ErrorAction SilentlyContinue | ForEach-Object { Write-Host (\$_.Name + ': ' + (Get-Content \$_.FullName -Raw -ErrorAction SilentlyContinue)) }; Start-Sleep -Seconds 2}\"" \
  2>&1 | sed 's/^/[VM-TAIL] /' &
TAIL_PID=$!

# 9. Run orchestrator AS lowuser via the existing run-as-lowuser harness.
#    Pass -mode through to the orchestrator. The harness wraps schtasks
#    /Run lowuser-context, captures stdout+stderr, surfaces the exit code
#    via the ###RC=<n> sentinel.
log "executing privesc-e2e.exe AS ${LOWUSER} (mode=${MODE}) — this can take 60-90s"
OUT=$(ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST_IP}" \
  "powershell -ExecutionPolicy Bypass -File C:\\Users\\${SSH_USER}\\run-as-lowuser.ps1 -Binary \"C:\\Users\\Public\\maldev\\privesc-e2e.exe\" -BinaryArgs \"-mode ${MODE}\" -UserName ${LOWUSER} -Password \"${LOWPASS}\" -TimeoutSeconds 90" \
  2>&1) || true
kill $TAIL_PID 2>/dev/null || true

echo "----- run-as-lowuser output -----"
echo "$OUT"
echo "----- end -----"

RC=$(echo "$OUT" | grep -oE '###RC=-?[0-9]+' | tail -1 | sed 's/###RC=//')
log "orchestrator exit code: ${RC:-<missing>}"

# 9. Fetch marker + victim log for the verdict
log "fetching marker + victim log"
mkdir -p ignore/privesc-e2e
scp "${SSH_OPTS[@]}" \
    "${SSH_USER}@${HOST_IP}:C:/ProgramData/maldev-marker/whoami.txt" \
    ignore/privesc-e2e/whoami.txt 2>/dev/null || log "no whoami.txt produced"
scp "${SSH_OPTS[@]}" \
    "${SSH_USER}@${HOST_IP}:C:/ProgramData/maldev-marker/victim.log" \
    ignore/privesc-e2e/victim.log 2>/dev/null || log "no victim.log produced"

# 10. Verdict
echo
echo "===================== VERDICT (mode ${MODE}) ====================="
if [ -f ignore/privesc-e2e/whoami.txt ]; then
    echo "marker: $(cat ignore/privesc-e2e/whoami.txt)"
fi
if [ -f ignore/privesc-e2e/victim.log ]; then
    echo "victim.log:"
    sed 's/^/    /' ignore/privesc-e2e/victim.log
fi
echo "================================================================"

if [ -f ignore/privesc-e2e/whoami.txt ] && grep -qi 'system' ignore/privesc-e2e/whoami.txt; then
    log "✅ SUCCESS — payload ran as SYSTEM (mode ${MODE})"
    trap - EXIT
    "$VBOX" controlvm "$VM_NAME" poweroff &>/dev/null || true
    sleep 3
    "$VBOX" snapshot "$VM_NAME" restore "$SNAPSHOT" &>/dev/null
    exit 0
fi

fail "marker missing or did not show SYSTEM identity"
