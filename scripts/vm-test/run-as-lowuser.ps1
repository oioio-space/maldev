# run-as-lowuser.ps1 — schedule a one-shot task that runs $Binary as $UserName
# with $Password, wait for completion, capture stdout+stderr, surface the
# task's LastTaskResult as the script exit code.
#
# Sidesteps the ssh-as-lowuser strict-mode / SeNetworkLogonRight rabbit hole
# by routing the unprivileged execution through the Task Scheduler service,
# which is the canonical mechanism real-world malware also uses.
param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$UserName,
    [Parameter(Mandatory=$true)][string]$Password,
    [int]$TimeoutSeconds = 120
)

# Use 'Continue' globally because schtasks writes "file not found" to
# stderr on idempotent /Delete calls — under 'Stop', PowerShell promotes
# native-tool stderr to a terminating error. We check $LASTEXITCODE
# explicitly where it actually matters.
$ErrorActionPreference = 'Continue'
$taskName = 'MaldevExampleRun'
$workDir  = 'C:\Users\Public\maldev'
$outFile  = Join-Path $workDir 'out.txt'
$shim     = Join-Path $workDir 'run.cmd'

# 1. Write the cmd shim that runs the binary and redirects both streams.
$shimBody = "@echo off`r`n""$Binary"" > ""$outFile"" 2>&1`r`nexit /b %errorlevel%`r`n"
Set-Content -Path $shim -Value $shimBody -Encoding ASCII -NoNewline

# 2. Tear down any leftover from a previous run.
schtasks /Delete /TN $taskName /F *> $null
if (Test-Path $outFile) { Remove-Item $outFile -Force }

# 3. Register and start the task. *> redirects ALL streams to $null so
#    schtasks's noisy success line ("Operation reussie...") doesn't pollute
#    the captured stdout we hand back to the host.
schtasks /Create /TN $taskName /TR "$shim" /SC ONCE /ST 23:59 `
         /RU $UserName /RP $Password /RL LIMITED /F *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "###RC=$LASTEXITCODE"; exit 0 }
schtasks /Run /TN $taskName *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "###RC=$LASTEXITCODE"; exit 0 }

# 4. Poll LastTaskResult via the typed cmdlet (locale-independent).
#    267011 = "task has not yet run", 267009 = "task is currently running".
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$rc = $null
while ((Get-Date) -lt $deadline) {
    $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
    if ($info) {
        $rc = [int]$info.LastTaskResult
        if ($rc -ne 267011 -and $rc -ne 267009) { break }
    }
    Start-Sleep -Milliseconds 300
}

# 5. Print the redirected output, then the sentinel line. The host parses
#    "###RC=<n>" as the source of truth for the exit code.
if (Test-Path $outFile) {
    Get-Content -Path $outFile -Raw
}
Write-Host ""
Write-Host "###RC=$rc"

# 6. Tear down. Output is already streamed by this point.
schtasks /Delete /TN $taskName /F *> $null
exit 0
