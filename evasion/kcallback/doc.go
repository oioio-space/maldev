//go:build windows

// Package kcallback enumerates and removes kernel-mode callback
// registrations that EDR products use to observe process/thread/image-
// load events from the kernel side.
//
// Reads the ntoskrnl callback arrays (`PspCreateProcessNotifyRoutine`,
// `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine`) via a
// caller-supplied KernelReader / KernelReadWriter. When backed by a
// driver-level primitive (BYOVD like RTCore64, GDRV, or a dedicated
// signed driver), the package reports which routines are registered
// and by which driver, then optionally zeroes the chosen slot under a
// refcount-aware RemoveToken so Restore puts the original value back
// without callers tracking the displaced bytes.
//
// `NtoskrnlBase` resolves the kernel image base via
// `SystemModuleInformation` (requires `SeDebugPrivilege`). `DriverAt`
// resolves a callback-array address to its hosting driver name.
//
// # MITRE ATT&CK
//
//   - T1562.001 (Impair Defenses: Disable or Modify Tools) —
//     kernel-mode analogue of user-mode hook removal
//
// # Detection level
//
// very-noisy
//
// The BYOVD driver load is the loudest event — Win10/11 HVCI blocks
// unsigned drivers; the attested-driver list is audited; Defender
// Driver Block-list catches RTCore64. After the slot is zeroed the
// EDR simply stops getting callbacks and may report itself as
// "running" (silent failure for blue), but the driver-load forensics
// still mark the host.
//
// # Required privileges
//
// kernel. Reads + writes target ntoskrnl-resident
// callback arrays via a caller-supplied
// KernelReader / KernelReadWriter — typically a BYOVD
// driver such as RTCore64. Loading that driver requires
// admin to install the service; the read/write itself
// runs at ring-0 once the driver is loaded. Pure-Go
// helpers (`NtoskrnlBase`, `DriverAt`) need
// `SeDebugPrivilege` (admin) for the
// `SystemModuleInformation` query.
//
// # Platform
//
// Windows-only (`//go:build windows`). The kernel
// callback arrays are Windows-specific surfaces.
// HVCI / Defender Driver Block-list / attested-driver
// list interact with the technique on modern Win10/11
// hosts (see Limitations in the tech md).
//
// # Example
//
// See [ExampleNtoskrnlBase] in kcallback_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/kernel-callback-removal.md
//   - [github.com/oioio-space/maldev/kernel/driver/rtcore64] — BYOVD KernelReadWriter
//
// [github.com/oioio-space/maldev/kernel/driver/rtcore64]: https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver/rtcore64
package kcallback
