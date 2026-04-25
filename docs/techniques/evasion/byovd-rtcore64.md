# BYOVD — RTCore64 (CVE-2019-16098)

[<- Back to Evasion](README.md)

**MITRE ATT&CK:** [T1014 — Rootkit](https://attack.mitre.org/techniques/T1014/) +
[T1543.003 — Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
**Package:** `kernel/driver/rtcore64`
**Platform:** Windows amd64
**Detection:** High during driver load; Medium steady-state

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
