# provision-lowuser.ps1 — idempotent provisioning of an unprivileged Windows
# user used to run maldev examples via scheduled tasks (avoids the OpenSSH
# strict-mode / profile / SeNetworkLogonRight rabbit hole that blocks direct
# ssh-as-lowuser on a freshly created local account).
#
# The host caller passes the password it intends to use when scheduling the
# task; we (re)set it on the SAM account so the two stay in sync. INIT
# snapshots wipe the account, so a fixed password per VM is acceptable.
#
# Usage (from the host, via ssh as the existing admin `test`):
#   ssh test@<vm> "powershell -File C:\path\to\provision-lowuser.ps1 -Password 'MaldevLow42!'"
param(
    [Parameter(Mandatory=$true)][string]$Password,
    [string]$UserName = 'lowuser'
)

$ErrorActionPreference = 'Stop'

# 1. Create the user with the supplied password (idempotent). The host needs
#    to know the password to schedule tasks running as this user, so we don't
#    randomize it; a fresh INIT snapshot wipes the account anyway.
$securePwd = ConvertTo-SecureString $Password -AsPlainText -Force
if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $UserName -Password $securePwd -PasswordNeverExpires `
                  -AccountNeverExpires `
                  -FullName 'Maldev low-priv runner' `
                  -Description 'Created by provision-lowuser.ps1' | Out-Null
    Write-Host "[+] created $UserName"
} else {
    # Force-reset the password so the host always knows the current value.
    Set-LocalUser -Name $UserName -Password $securePwd
    Write-Host "[=] $UserName already exists, password reset"
}
# Force PASSWD_REQUIRED — New-LocalUser leaves PASSWD_NOTREQD set in some
# Windows builds, which blocks scheduled-task / network logons.
net user $UserName /passwordreq:yes 2>&1 | Out-Null

# Add lowuser to the local Users group (SID S-1-5-32-545) so it gets the
# default SeNetworkLogonRight — required for OpenSSH network logon. Use
# the SID rather than the name because Windows localizes "Users" → e.g.
# "Utilisateurs" on a French SKU.
$usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
$inUsers = Get-LocalGroupMember -Group $usersGroup -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -match "\\$UserName$" }
if (-not $inUsers) {
    Add-LocalGroupMember -Group $usersGroup -Member $UserName
    Write-Host "[+] added $UserName to $($usersGroup.Name)"
}

# 2. Grant SeBatchLogonRight ("logon as batch job") so the Task Scheduler
#    can actually start a task that runs as lowuser. Members of Users do
#    NOT have this right by default; without it `schtasks /Create /RU
#    lowuser` succeeds but the task never starts. We patch the local
#    security policy via secedit which is built-in on every Windows SKU.
$sid = (New-Object Security.Principal.NTAccount $UserName).Translate(
        [Security.Principal.SecurityIdentifier]).Value
$cfg = Join-Path $env:TEMP 'maldev-secpol.inf'
$db  = Join-Path $env:TEMP 'maldev-secpol.sdb'
secedit /export /cfg $cfg /areas USER_RIGHTS *> $null
$current = Get-Content $cfg
# Skip secedit /configure when the SID is already present — it rewrites the
# LSA policy DB and takes ~1s; a no-op run wastes that on every repeat.
$alreadyGranted = $current | Where-Object {
    $_ -match '^SeBatchLogonRight\s*=' -and $_ -match [regex]::Escape($sid)
}
if ($alreadyGranted) {
    Write-Host "[=] $UserName already has SeBatchLogonRight"
} else {
    $patched = $false
    $out = foreach ($line in $current) {
        if ($line -match '^SeBatchLogonRight\s*=') {
            $patched = $true
            "$line,*$sid"
        } else { $line }
    }
    if (-not $patched) { $out += "SeBatchLogonRight = *$sid" }
    $out | Set-Content $cfg -Encoding Unicode
    secedit /configure /db $db /cfg $cfg /areas USER_RIGHTS *> $null
    Write-Host "[+] $UserName granted SeBatchLogonRight"
}
Remove-Item $cfg, $db -Force -ErrorAction SilentlyContinue

# 3. Grant lowuser write access to a scratch dir under C:\Users\Public\maldev
#    so the scheduled-task runner can read the binary and write output there.
$workDir = 'C:\Users\Public\maldev'
if (-not (Test-Path $workDir)) {
    New-Item -ItemType Directory -Path $workDir | Out-Null
}
icacls $workDir /grant "${UserName}:(OI)(CI)F" | Out-Null
Write-Host "[+] $workDir writable by $UserName"

Write-Host "[+] $UserName ready as scheduled-task runner"

# 3. Echo the runtime fingerprint so the host can sanity-check the SAM state.
$u = Get-LocalUser $UserName
Write-Host ("[i] sid={0} enabled={1}" -f $u.SID.Value, $u.Enabled)
