# vm-test.ps1 — Run Go tests from VirtualBox shared folder
# Usage: powershell -File Z:\scripts\vm-test.ps1 -Packages "./persistence/registry/" -Flags "-v -count=1"
param(
    [string]$Packages = "./...",
    [string]$Flags = "-count=1"
)

$ErrorActionPreference = "Continue"

# Copy project to local disk (Go modules don't work on UNC paths)
if (Test-Path C:\maldev) { Remove-Item C:\maldev -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host "Copying project to C:\maldev..."
robocopy Z:\ C:\maldev /E /NFL /NDL /NJH /NJS /XD .git ignore | Out-Null
Write-Host "Copy done."

Set-Location C:\maldev
Write-Host "Running: go test $Packages $Flags"
$goArgs = @("test") + $Packages.Split(" ") + $Flags.Split(" ")
& go @goArgs
$exitCode = $LASTEXITCODE
Write-Host "VM_TEST_EXIT_CODE=$exitCode"
exit $exitCode
