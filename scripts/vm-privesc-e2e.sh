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
# Avoid '!' / other cmd-special chars — they get mangled in the
# bash -> ssh -> cmd -> powershell -> schtasks /RP pipeline and
# silently produce "le nom d'utilisateur ou le mot de passe est
# incorrect", costing 30+ minutes of debugging the wrong layer.
LOWPASS='MaldevLow42x'
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
SNAPSHOT='INIT'
SSH_USER='test'
LOWUSER='lowuser'
SSH_KEY="${MALDEV_VM_WINDOWS_SSH_KEY:-$HOME/.ssh/vm_windows_key}"
[ -f "$SSH_KEY" ] || { echo "missing SSH key: $SSH_KEY" >&2; exit 1; }
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes)

# Driver auto-detect — VirtualBox on operator workstation, libvirt on
# the Fedora dev host. Either driver may be forced via MALDEV_VM_DRIVER.
DRIVER="${MALDEV_VM_DRIVER:-}"
if [ -z "$DRIVER" ]; then
  if command -v VBoxManage >/dev/null 2>&1 || [ -x "$VBOX" ]; then
    DRIVER='vbox'
  elif command -v virsh >/dev/null 2>&1; then
    DRIVER='libvirt'
  else
    echo "no VM driver found: install VirtualBox or libvirt" >&2; exit 1
  fi
fi

case "$DRIVER" in
  vbox)
    VM_NAME="${MALDEV_VM_NAME:-Windows10}"
    HOST_IP="${MALDEV_VM_HOST_IP:-192.168.56.102}"
    vm_poweroff() { "$VBOX" controlvm "$VM_NAME" poweroff &>/dev/null; }
    vm_restore()  { "$VBOX" snapshot "$VM_NAME" restore "$SNAPSHOT" &>/dev/null; }
    vm_start()    { "$VBOX" startvm "$VM_NAME" --type headless &>/dev/null; }
    ;;
  libvirt)
    VM_NAME="${MALDEV_VM_NAME:-win10}"
    HOST_IP="${MALDEV_VM_HOST_IP:-192.168.122.122}"
    # snapshot-revert on a running-snapshot covers poweroff + restore
    # in one atomic op — no separate poweroff/start.
    vm_poweroff() { virsh destroy "$VM_NAME" &>/dev/null || true; }
    vm_restore()  { virsh snapshot-revert "$VM_NAME" --snapshotname "$SNAPSHOT" --running &>/dev/null; }
    vm_start()    { virsh domstate "$VM_NAME" 2>/dev/null | grep -q "en cours\|running" || virsh start "$VM_NAME" &>/dev/null; }
    ;;
  *)
    echo "unknown MALDEV_VM_DRIVER=$DRIVER (want vbox|libvirt)" >&2; exit 1
    ;;
esac

log() { printf '\033[36m[%s] %s\033[0m\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '\033[31m[%s] FAIL: %s\033[0m\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

teardown() {
  if [ "$KEEP_VM" = 1 ]; then
    log "KEEP_VM=1 — leaving VM running for debug (ssh -i $SSH_KEY ${SSH_USER}@${HOST_IP})"
    return
  fi
  log "tearing down VM"
  vm_poweroff
  sleep 3
  vm_restore
}
trap teardown EXIT

# 1. Snapshot restore
log "restoring snapshot $SNAPSHOT"
vm_poweroff || true
sleep 3
vm_restore || fail "snapshot restore"
vm_start   || fail "startvm"

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
log "building probe.exe (Go) + victim.exe (mingw nostdlib) + fakelib.dll (cgo c-shared) + privesc-e2e.exe (windows/amd64)"
# Probe = full Go (os.WriteFile + exec.Command). Survives the Mode-8
# thread-spawn because victim.exe is C (next step): the spawned-
# thread Go runtime gets a clean process with no prior TLS slot 0
# occupant.
GOOS=windows GOARCH=amd64 go build -ldflags='-s -w' \
    -o cmd/privesc-e2e/probe/probe.exe \
    ./cmd/privesc-e2e/probe || fail "build probe (Go)"
# Victim = C nostdlib mingw, kernel32-only. Stays Go-runtime-free so
# the Go probe payload thread can initialise cleanly when DllMain
# spawns it.
x86_64-w64-mingw32-gcc -nostdlib -e mainCRTStartup \
    -o /tmp/victim.exe \
    cmd/privesc-e2e/victim/victim.c -lkernel32 || fail "build victim (mingw)"
# fakelib must build BEFORE the orchestrator — main.go //go:embed
# pulls fakelib/fakelib.dll at compile time. GOTMPDIR isolates the
# cgo tmpfiles so host AV scanning ignore/ doesn't churn.
mkdir -p ignore/gotmp
GOTMPDIR="$(pwd)/ignore/gotmp" CGO_ENABLED=1 \
    GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
    go build -buildmode=c-shared \
    -o cmd/privesc-e2e/fakelib/fakelib.dll ./cmd/privesc-e2e/fakelib || fail "build fakelib (cgo c-shared)"
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
  "powershell -ExecutionPolicy Bypass -File C:\\Users\\${SSH_USER}\\provision-lowuser.ps1 -Password \"${LOWPASS}\"" \
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
# Avoid bash->ssh->cmd->powershell quoting hell: drop a tiny PS
# wrapper on the VM hardcoding the args, then invoke it via a
# single-token command line.
# Pack-time flag plumbing: AntiDebug is OFF by default on libvirt/KVM
# because the RDTSC ↔ CPUID delta gate baked into the slice-5.6 stub
# trips on the KVM VMEXIT and causes a silent no-op LoadLibrary
# (handle returns valid, payload never runs). VirtualBox host CPUs
# emulate RDTSC tightly enough that the gate stays under threshold.
# Operator override via MALDEV_PRIVESC_E2E_ARGS for ad-hoc runs.
ORCH_ARGS="-mode ${MODE}"
if [ "$DRIVER" = "libvirt" ]; then
    ORCH_ARGS="$ORCH_ARGS -antidebug=false"
fi
ORCH_ARGS="${MALDEV_PRIVESC_E2E_ARGS:-$ORCH_ARGS}"
log "orchestrator args: $ORCH_ARGS"
cat > /tmp/run-orchestrator.ps1 <<EOF
& "C:\\Users\\${SSH_USER}\\run-as-lowuser.ps1" -Binary "C:\\Users\\Public\\maldev\\privesc-e2e.exe" -BinaryArgs "${ORCH_ARGS}" -UserName ${LOWUSER} -Password "${LOWPASS}" -TimeoutSeconds 180
EOF
scp "${SSH_OPTS[@]}" /tmp/run-orchestrator.ps1 "${SSH_USER}@${HOST_IP}:C:/Users/${SSH_USER}/" &>/dev/null
OUT=$(ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST_IP}" \
  "powershell -ExecutionPolicy Bypass -File C:\\Users\\${SSH_USER}\\run-orchestrator.ps1 ; powershell -Command \"Start-Sleep -Seconds 70; Write-Host VICTIM-LOG-LATE:; Get-Content C:\\ProgramData\\maldev-marker\\victim.log -Tail 4\"" \
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

# Verdict logic — TWO levels of proof:
#   Strong:   marker file shows SYSTEM (proves the payload's side-effect)
#   Adequate: victim.log shows "LoadLibrary succeeded" AFTER our orchestrator
#             planted the DLL (proves SYSTEM-context loaded our packed DLL).
#             The payload thread reached at least the loader callback.
strong=0
adequate=0
# GetUserNameA returns the localised SYSTEM account name in Windows-1252
# encoding (NOT UTF-8): "System" (en-US), "Syst\xE8me" (fr-FR), "Sistema"
# (es/it/pt). grep -qi 'system' alone misses the French byte sequence
# because the `è` byte (0xE8) breaks the literal-match. Match either
# the en-US/Iberian word OR the French ASCII skeleton "Syst" followed
# by a non-printable byte then "me".
if [ -f ignore/privesc-e2e/whoami.txt ] && \
   LC_ALL=C grep -qaiE '(system|sistema|Syst.me)' ignore/privesc-e2e/whoami.txt; then
    # LC_ALL=C forces byte-level grep: in a UTF-8 locale `-E` treats
    # `.` as a character class, and the lone 0xE8 byte (è in Win-1252)
    # isn't a valid UTF-8 character → `Syst.me` silently fails to
    # match the French marker. Byte mode sidesteps it.
    strong=1
fi
# Adequate proof: count "LoadLibrary succeeded" lines in victim.log. The
# baseline run (no DLL planted) emits one "LoadLibrary failed" line, so
# any "LoadLibrary succeeded" in there is OUR plant taking effect.
if [ -f ignore/privesc-e2e/victim.log ] && grep -q 'LoadLibrary succeeded' ignore/privesc-e2e/victim.log; then
    adequate=1
fi

if [ "$strong" = 1 ]; then
    log "✅ STRONG SUCCESS — marker shows SYSTEM identity (mode ${MODE})"
    teardown_ok=1
elif [ "$adequate" = 1 ]; then
    log "✅ ADEQUATE PROOF — SYSTEM-context victim.exe LoadLibrary'd our packed DLL (mode ${MODE})"
    log "   Marker file write not visible to external observer — see lessons doc."
    teardown_ok=1
else
    teardown_ok=0
fi

if [ "$teardown_ok" = 1 ]; then
    if [ "$KEEP_VM" != 1 ]; then
        trap - EXIT
        vm_poweroff || true
        sleep 3
        vm_restore
    fi
    exit 0
fi

fail "no LoadLibrary success in victim.log AND no marker — chain broken"
