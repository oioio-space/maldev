# Caller / Opener / folder.Get coverage audit — 2026-04-26

Audit of the maldev tree to identify production sites that should
accept stealth-routing parameters (`*wsyscall.Caller`,
`stealthopen.Opener`) or use `recon/folder.Get(CSIDL_*)` instead of
PEB env-var sniffs.

## Context

CLAUDE.md rule: *"NtXxx calls accept optional `*wsyscall.Caller`
(kernel32-only exempt)"*. The pattern is also expected for path-based
file reads (`stealthopen.Opener`) and Windows special-folder
resolution (`recon/folder.Get`).

The v0.32.0 lsass cleanup wired Caller / Opener / folder.Get into
`credentials/sekurlsa.ParseFile`, `credentials/lsassdump.Discover*Offset`,
`credentials/lsassdump.FindLsassEProcess`, and the
`defaultNtoskrnlPath` helper. This audit covers everything else.

## Findings

### Caller — Nt* calls without optional `*wsyscall.Caller`

**HIGH** (production credential / privesc / tamper code; high
operational frequency, EDR detection-relevant):

| Site | Function | Nt* call | Status |
|------|----------|----------|--------|
| `inject/kcallback_windows.go:54` | `KernelCallbackExec` | `NtQueryInformationProcess` | **fixed 2026-04-26** (worked example) |
| `inject/spoofargs_windows.go:78` | `SpawnWithSpoofedArgs` | `NtQueryInformationProcess` | open — task #v0.33.0-caller-spoofargs |
| `privesc/cve202430088/race.go:263` | token TOCTOU race | `NtQueryInformationToken` | open — task #v0.33.0-caller-cve202430088 |
| `process/tamper/phant0m/phant0m_windows.go:71` | `isEventLogThread` | `NtQueryInformationThread` | open — task #v0.33.0-caller-phant0m |

**MEDIUM** (production injection helpers; lower frequency, often
called via the parent inject API):

| Site | Function | Nt* call |
|------|----------|----------|
| `inject/callback_windows.go:245` | `executeRtlRegisterWait` | `RtlRegisterWait` (technically not Nt* but EDR-relevant) |
| `inject/callback_windows.go:279` | `executeNtNotifyChange` | `NtNotifyChangeDirectoryFile` |
| `inject/injector_self_windows.go:71` | `injectCreateThread` | `NtCreateThreadEx` |
| `inject/injector_remote_windows.go:282` | `injectRtlCreateUserThread` | `RtlCreateUserThread` |
| `inject/injector_remote_windows.go:359` | `injectNtQueueApcThreadEx` | `NtQueueApcThreadEx` |

**LOW**:

| Site | Function | Notes |
|------|----------|-------|
| `evasion/kcallback/drivers_windows.go:62,71` | `fetchLoadedModules` | `NtQuerySystemInformation` — module enumeration cached once at load |

### Opener — `os.Open` without optional `stealthopen.Opener`

**No active gaps.** `inject/phantomdll_windows.go` already accepts
`opener` correctly; everywhere else either reads non-sensitive paths
(configs, `/proc`, dev tools) or writes (where Opener doesn't apply).

### folder.Get — `os.Getenv("SYSTEMROOT|TEMP|...")` on Windows

**HIGH**:

| Site | Function | Env var | Status |
|------|----------|---------|--------|
| `inject/phantomdll_windows.go:46` | `PhantomDLLInject` | `SYSTEMROOT` → CSIDL_SYSTEM | **fixed 2026-04-26** |

**MEDIUM**:

| Site | Function | Env var | Notes |
|------|----------|---------|-------|
| `kernel/driver/rtcore64/rtcore64_windows.go:168` | `dropDriver` | `WINDIR` → CSIDL_WINDOWS | drops driver to disk; switch when touched next |

**LOW**:

| Site | Function | Env var | Notes |
|------|----------|---------|-------|
| `recon/dllhijack/validate_windows.go:54` | `defaults` | `ProgramData` → CSIDL_COMMON_APPDATA | marker poll location, low-sensitivity |

## Decisions

- **Fixed in this audit pass** (2 sites): `KernelCallbackExec` Caller
  + `PhantomDLLInject` folder.Get. Worked examples for the pattern.
- **Deferred to v0.33.0** (8 sites): each remaining Caller addition
  is an exported-API break that deserves its own commit + reviewer
  pass. Bundling them risks losing per-site context (different Nt*
  calls have different argument shapes / error semantics).
- **`evasion/kcallback/drivers_windows.go`** stays as-is: the module
  enumeration runs once at load time and the result is cached, so the
  Caller routing benefit is small.
- **rtcore64.dropDriver `WINDIR`** to convert next time the file is
  touched for an unrelated reason — not worth a dedicated commit.
- **dllhijack.defaults `ProgramData`** stays — non-sensitive marker
  poll, no operational benefit from CSIDL switch.

## Pattern reference (for v0.33.0 follow-ups)

The dispatch helper added to `inject/kcallback_windows.go` is the
canonical pattern:

```go
func queryProcessBasicInfo(caller *wsyscall.Caller, hProcess uintptr,
    pbi *processBasicInfo, retLen *uint32) (uintptr, error) {
    if caller != nil {
        status, err := caller.Call("NtQueryInformationProcess",
            hProcess, 0,
            uintptr(unsafe.Pointer(pbi)),
            unsafe.Sizeof(*pbi),
            uintptr(unsafe.Pointer(retLen)),
        )
        return status, err
    }
    status, _, _ := api.ProcNtQueryInformationProcess.Call(
        hProcess, 0,
        uintptr(unsafe.Pointer(pbi)),
        unsafe.Sizeof(*pbi),
        uintptr(unsafe.Pointer(retLen)),
    )
    return status, nil
}
```

The exported function adds `caller *wsyscall.Caller` as the last
parameter; nil falls back to the WinAPI proc-table call.

For `folder.Get`:

```go
sys32 := folder.Get(folder.CSIDL_SYSTEM, false)
if sys32 == "" {
    return fmt.Errorf("FuncName: SHGetSpecialFolderPathW(CSIDL_SYSTEM) returned empty")
}
```
