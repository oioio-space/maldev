# vm-debug-tools.ps1 — install heavyweight debugging tools on
# the Win10 test VM for cases the WER LocalDumps + empirical
# bisection workflow can't crack alone.
#
# NOT wired into vm-provision.sh by default — those tools add
# ~600 MiB to the snapshot. Run manually when needed:
#
#   scp scripts/vm-debug-tools.ps1 test@<win10-ip>:C:/Users/test/
#   ssh test@<win10-ip> "powershell -ExecutionPolicy Bypass -File C:\Users\test\vm-debug-tools.ps1"
#
# Idempotent: every install path short-circuits when the tool
# is already present.

$ErrorActionPreference = 'Stop'

# 1. Sysinternals Suite (single zip, ~50 MiB) — gives us
#    procmon (filesystem/registry tracing), procexp (handle
#    inspector), Strings (PE string dump), etc.
$SysInternalsDir = "C:\Tools\Sysinternals"
if (-not (Test-Path "$SysInternalsDir\procmon64.exe")) {
    Write-Host "Installing Sysinternals Suite..."
    New-Item -ItemType Directory -Force -Path $SysInternalsDir | Out-Null
    $zip = "$env:TEMP\SysinternalsSuite.zip"
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" `
        -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $SysInternalsDir -Force
    Remove-Item $zip
} else {
    Write-Host "Sysinternals Suite already installed at $SysInternalsDir"
}

# 2. Windows SDK Debugging Tools (cdb.exe, windbg.exe). The
#    full SDK is ~3 GiB; we install only the Debugging Tools
#    feature (~150 MiB).
#    Bootstrap via the standalone winsdksetup.exe with
#    /features OptionId.WindowsDesktopDebuggers.
$DebuggersDir = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
if (-not (Test-Path "$DebuggersDir\cdb.exe")) {
    Write-Host "Installing Windows SDK Debugging Tools..."
    $sdkInstaller = "$env:TEMP\winsdksetup.exe"
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2196241" `
        -OutFile $sdkInstaller -UseBasicParsing
    Start-Process -FilePath $sdkInstaller `
        -ArgumentList @('/features', 'OptionId.WindowsDesktopDebuggers',
                        '/q', '/norestart') `
        -Wait -NoNewWindow
    Remove-Item $sdkInstaller
} else {
    Write-Host "Windows SDK Debuggers already installed at $DebuggersDir"
}

# 3. PATH update so cdb.exe / procmon64.exe are reachable from
#    SSH sessions without typing full paths.
$paths = @($SysInternalsDir, $DebuggersDir)
$current = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
foreach ($p in $paths) {
    if ($current -notlike "*$p*") {
        $current = "$current;$p"
    }
}
[System.Environment]::SetEnvironmentVariable('Path', $current, 'Machine')

Write-Host ""
Write-Host "Done. Available now (after a new shell):"
Write-Host "  procmon64.exe       — filesystem/registry tracer"
Write-Host "  cdb.exe             — command-line crash analyzer"
Write-Host "  windbg.exe          — full debugger (TUI)"
Write-Host "  C:\Dumps\           — WER minidumps (already configured)"
