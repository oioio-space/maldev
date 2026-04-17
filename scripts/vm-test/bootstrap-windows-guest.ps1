# bootstrap-windows-guest.ps1 — run INSIDE a fresh Windows 10/11 VM
# (elevated PowerShell — right-click "Run as administrator") to bring it
# to the ready state expected by vmtest and memscan.
#
# Usage:
#   .\bootstrap-windows-guest.ps1 -PublicKey "ssh-ed25519 AAAA... maldev-vmtest-windows"
#
# Idempotent: running twice leaves the system in the same state.
#
# Parameters:
#   -PublicKey    (required) host's SSH public key for user `test`
#   -User         default 'test'
#   -GoVersion    default 1.26.2

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PublicKey,
    [string] $User      = 'test',
    [string] $GoVersion = '1.26.2'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Log { param($m) Write-Host "[bootstrap] $m" -ForegroundColor Cyan }

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    throw "must run as Administrator (right-click PowerShell -> Run as administrator)"
}

# 1. OpenSSH Server
if ((Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0).State -ne 'Installed') {
    Log 'installing OpenSSH.Server capability'
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
} else {
    Log 'OpenSSH.Server already installed'
}

Log 'starting + enabling sshd'
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# 2. Firewall rules
foreach ($rule in @(
        @{ Name='ssh-in';      Port=22 },
        @{ Name='memscan-in';  Port=50300 })) {
    if (-not (Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue)) {
        Log "creating firewall rule $($rule.Name) (TCP $($rule.Port) inbound)"
        New-NetFirewallRule -Name $rule.Name `
            -DisplayName "maldev $($rule.Name)" `
            -Direction Inbound -Protocol TCP -LocalPort $rule.Port -Action Allow | Out-Null
    }
}

# 3. authorized_keys for $User
$sshHome = "C:\Users\$User\.ssh"
if (-not (Test-Path $sshHome)) {
    Log "creating $sshHome"
    New-Item -ItemType Directory -Force -Path $sshHome | Out-Null
}
$authFile = Join-Path $sshHome 'authorized_keys'
$existing = if (Test-Path $authFile) { Get-Content $authFile } else { @() }
if ($existing -notcontains $PublicKey) {
    Log "appending public key to $authFile"
    # UTF-8 no-BOM, LF terminator — OpenSSH is picky.
    $lines = @($existing) + $PublicKey
    [IO.File]::WriteAllLines($authFile, $lines, [Text.UTF8Encoding]::new($false))
}

Log "setting strict ACL on authorized_keys"
icacls $authFile /inheritance:r /grant "${User}:F" /grant "SYSTEM:F" | Out-Null

# 4. sshd_config: if $User is admin, comment the Match Group administrators
#    block so per-user authorized_keys is read instead of
#    %ProgramData%\ssh\administrators_authorized_keys.
$groups = (whoami /groups) -join ' '
$isAdmin = $groups -match 'S-1-5-32-544'   # Administrators SID (locale-independent)
$cfgPath = "$env:ProgramData\ssh\sshd_config"
if ($isAdmin -or ((Get-Content $cfgPath) -match '^Match Group administrators')) {
    Log "patching sshd_config: commenting Match Group administrators block"
    $new = @()
    $inMatch = $false
    foreach ($l in Get-Content $cfgPath) {
        if ($l -match '^\s*Match\s+Group\s+administrators') {
            $inMatch = $true; $new += "# $l"; continue
        }
        if ($inMatch -and $l -match '^\s+AuthorizedKeysFile') {
            $new += "#$l"; $inMatch = $false; continue
        }
        $new += $l
    }
    Set-Content -Path $cfgPath -Value $new -Encoding ASCII
    Restart-Service sshd
}

# 5. Go install to C:\Go + system PATH
if ((Test-Path 'C:\Go\bin\go.exe') -and (& 'C:\Go\bin\go.exe' version) -match "go$GoVersion ") {
    Log "Go $GoVersion already installed"
} else {
    Log "installing Go $GoVersion"
    $zip = Join-Path $env:TEMP 'go.zip'
    Invoke-WebRequest "https://go.dev/dl/go$GoVersion.windows-amd64.zip" -OutFile $zip -UseBasicParsing
    if (Test-Path C:\Go) { Remove-Item C:\Go -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath C:\ -Force
    Remove-Item $zip
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($machinePath -notlike '*C:\Go\bin*') {
        [Environment]::SetEnvironmentVariable('Path', "$machinePath;C:\Go\bin", 'Machine')
        Log 'added C:\Go\bin to Machine PATH'
    }
}

Log 'verifying'
& 'C:\Go\bin\go.exe' version
Get-Service sshd | Format-Table Name, Status -AutoSize

Log 'done. Take an INIT snapshot from the host side now.'
