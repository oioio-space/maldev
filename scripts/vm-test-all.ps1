# vm-test-all.ps1 — Run ALL Go tests including intrusive and manual
param(
    [string]$Packages = "./...",
    [string]$Flags = "-v -count=1 -timeout 300s"
)

$ErrorActionPreference = "Continue"

# Copy project to local disk
if (Test-Path C:\maldev) { Remove-Item C:\maldev -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host "Copying project to C:\maldev..."
robocopy Z:\ C:\maldev /E /NFL /NDL /NJH /NJS /XD .git ignore | Out-Null
Write-Host "Copy done."

Set-Location C:\maldev

# Enable all test gates
$env:MALDEV_INTRUSIVE = "1"
$env:MALDEV_MANUAL = "1"

Write-Host "Running: go test $Packages $Flags (INTRUSIVE=1 MANUAL=1)"
$goArgs = @("test") + $Packages.Split(" ") + $Flags.Split(" ")
& go @goArgs
$exitCode = $LASTEXITCODE
Write-Host "VM_TEST_EXIT_CODE=$exitCode"
exit $exitCode
