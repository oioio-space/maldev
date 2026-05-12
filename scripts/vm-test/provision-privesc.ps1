# provision-privesc.ps1 -- set up the DLL-hijack privesc E2E target
# on top of provision-lowuser.ps1's lowuser account.
#
# Idempotent. Each fresh INIT snapshot wipes everything; run again.
#
# Layout this script lays down:
#   C:\Vulnerable\                 (lowuser-writable, victim.exe lives here)
#   C:\Vulnerable\victim.exe       (LoadLibrary("hijackme.dll") -- sideload sink)
#   C:\ProgramData\maldev-marker\  (world-writable scratch for whoami marker + victim log)
#   Scheduled task "MaldevHijackVictim"
#     principal = SYSTEM
#     action    = C:\Vulnerable\victim.exe
#     ACL       = lowuser granted RX (read + execute / RUN) via SDDL patch
#
# The orchestrator (cmd/privesc-e2e) runs as lowuser, plants
# C:\Vulnerable\hijackme.dll, fires `schtasks /Run /TN MaldevHijackVictim`,
# polls C:\ProgramData\maldev-marker\whoami.txt, asserts SYSTEM identity.
#
# Usage from host (after provision-lowuser.ps1 ran):
#   scp scripts/vm-test/provision-privesc.ps1   test@<vm>:C:/Users/test/
#   scp /tmp/victim.exe                          test@<vm>:C:/Users/test/
#   ssh test@<vm> "powershell -File C:\Users\test\provision-privesc.ps1 \
#                    -VictimSource C:\Users\test\victim.exe"
param(
    [Parameter(Mandatory=$true)][string]$VictimSource,
    [string]$LowUser    = 'lowuser',
    [string]$VulnDir    = 'C:\Vulnerable',
    [string]$MarkerDir  = 'C:\ProgramData\maldev-marker',
    [string]$TaskName   = 'MaldevHijackVictim'
)

# Use 'Continue' globally because schtasks writes "file not found" to
# stderr on idempotent /Delete calls -- under 'Stop', PowerShell promotes
# native-tool stderr to a terminating error. We check $LASTEXITCODE
# explicitly where it actually matters (same pattern as run-as-lowuser.ps1).
$ErrorActionPreference = 'Continue'

if (-not (Test-Path $VictimSource)) {
    Write-Host "VictimSource not found: $VictimSource"
    exit 1
}

# 1. C:\Vulnerable\  -- writable by lowuser so the orchestrator can plant
#    hijackme.dll right next to victim.exe (DLL search-order win).
if (-not (Test-Path $VulnDir)) {
    New-Item -ItemType Directory -Path $VulnDir | Out-Null
    Write-Host "[+] created $VulnDir"
}
icacls $VulnDir /grant "${LowUser}:(OI)(CI)F" *> $null
Write-Host "[=] $VulnDir : lowuser=Modify"

# 2. Drop victim.exe (overwrite each run to pick up rebuilds).
$victimDest = Join-Path $VulnDir 'victim.exe'
Copy-Item -Force $VictimSource $victimDest
Write-Host "[+] deployed $victimDest"

# 3. Marker dir, world-writable (SYSTEM probe writes here, lowuser reads).
if (-not (Test-Path $MarkerDir)) {
    New-Item -ItemType Directory -Path $MarkerDir | Out-Null
}
# Use the well-known Everyone SID (S-1-1-0) so this works on
# localised SKUs (FR Windows has no "Everyone" account name).
icacls $MarkerDir /grant '*S-1-1-0:(OI)(CI)M' *> $null
Write-Host "[=] $MarkerDir : *S-1-1-0 (Everyone)=Modify"

# 4. Scheduled task -- runs victim.exe as SYSTEM on demand. /Run triggers
#    it from the lowuser orchestrator, which is the actual privesc primitive.
schtasks /Delete /TN $TaskName /F *> $null
$schArgs = @(
    '/Create', '/TN', $TaskName,
    '/TR', "`"$victimDest`"",
    # Auto-trigger every minute -- lowuser cannot /Run a SYSTEM task
    # via schtasks (RPC ACL distinct from the file ACL we patch
    # below), so we sidestep the permission with a self-trigger and
    # have the orchestrator just wait one cycle after planting the
    # DLL.
    '/SC', 'MINUTE', '/MO', '1',
    '/RU', 'SYSTEM',
    '/RL', 'HIGHEST',
    '/F'
)
schtasks @schArgs *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "schtasks /Create failed: $LASTEXITCODE"; exit 1 }
Write-Host "[+] task $TaskName : SYSTEM-context, action=$victimDest"

# 5. Patch the task's ACL so lowuser can /Run it. schtasks doesn't expose
#    permissions directly; we use Get-Acl on the task XML in
#    %WINDIR%\System32\Tasks\<TaskName>. SDDL ace 'A;;FRFX;;;<sid>' grants
#    file-read + file-execute = enough to trigger /Run.
$taskFile = Join-Path $env:WINDIR ('System32\Tasks\' + $TaskName)
if (-not (Test-Path $taskFile)) { Write-Host "task file not found: $taskFile"; exit 1 }
$lowSid = (New-Object Security.Principal.NTAccount $LowUser).Translate(
            [Security.Principal.SecurityIdentifier]).Value
$acl = Get-Acl $taskFile
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $LowUser,
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
    [System.Security.AccessControl.AccessControlType]::Allow)
$acl.AddAccessRule($rule)
Set-Acl -Path $taskFile -AclObject $acl
Write-Host "[+] task $TaskName : lowuser ($lowSid) granted ReadAndExecute (covers /Run)"

# 6. Smoke-test -- try /Run as the current admin (test) once to make sure the
#    plumbing works (no DLL planted yet -> victim's LoadLibrary will fail
#    cleanly and log "DLL not found"; that's the expected baseline).
schtasks /Run /TN $TaskName *> $null
Start-Sleep -Seconds 2
$victimLog = Join-Path $MarkerDir 'victim.log'
if (Test-Path $victimLog) {
    Write-Host "[i] baseline victim.log (no DLL planted yet):"
    Get-Content $victimLog | Select-Object -Last 3 | ForEach-Object { Write-Host "    $_" }
} else {
    Write-Host "[!] victim.log not produced after smoke /Run -- task may have failed"
}

Write-Host "[+] privesc target ready: lowuser -> /Run task -> victim.exe (SYSTEM) -> LoadLibrary(hijackme.dll)"

# 7. Defender exclusions for the test paths.
#    Direct registry write under
#    HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths --
#    avoids both Add-MpPreference (AMSI signature blocklist) AND
#    the AmsiUtils reflective bypass (also signature-flagged in
#    modern Defender). The registry path needs admin + no Tamper
#    Protection; check TP first, surface diagnostics either way.
$tpEnabled = $false
try {
    $tpEnabled = (Get-MpComputerStatus).IsTamperProtected
} catch {
    Write-Host "[!] Get-MpComputerStatus failed: $($_.Exception.Message)"
}
Write-Host "[i] TamperProtection enabled: $tpEnabled"

$regBase = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
$paths = @($VulnDir, $MarkerDir, 'C:\Users\Public\maldev')
$ok = 0
foreach ($p in $paths) {
    try {
        New-ItemProperty -Path $regBase -Name $p -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Host "[+] reg exclusion: $p"
        $ok++
    } catch {
        Write-Host "[!] reg exclusion failed for $p : $($_.Exception.Message)"
    }
}
if ($ok -lt $paths.Length -and $tpEnabled) {
    Write-Host "[!] some exclusions blocked AND Tamper Protection is ON --"
    Write-Host "    real-world bypass would require disabling TP via Settings UI"
    Write-Host "    or InTune policy (cannot be done programmatically by design)."
}
