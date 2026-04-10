# vm-test-realsc.ps1 — Run real shellcode tests with Defender suspended
param(
    [string]$Packages = "./inject/",
    [string]$RunFilter = "RealShellcode",
    [string]$Flags = "-v -count=1 -timeout 120s"
)

$ErrorActionPreference = "Continue"

# Copy project
if (Test-Path C:\maldev) { Remove-Item C:\maldev -Recurse -Force -EA SilentlyContinue }
robocopy Z:\ C:\maldev /E /NFL /NDL /NJH /NJS /XD .git ignore | Out-Null

# Suspend Defender
Write-Host "Suspending Defender..."
Set-MpPreference -DisableRealtimeMonitoring $true -EA SilentlyContinue

Set-Location C:\maldev
$env:MALDEV_INTRUSIVE = "1"
$env:MALDEV_MANUAL = "1"
$env:GOTRACEBACK = "all"

Write-Host "Running: go test $Packages -run $RunFilter $Flags"
$goArgs = @("test", $Packages, "-run", $RunFilter) + $Flags.Split(" ")
& go @goArgs 2>&1 | ForEach-Object { Write-Output $_ }
$exitCode = $LASTEXITCODE

# Re-enable Defender
Write-Host "Re-enabling Defender..."
Set-MpPreference -DisableRealtimeMonitoring $false -EA SilentlyContinue

Write-Host "EXIT_CODE=$exitCode"
exit $exitCode
