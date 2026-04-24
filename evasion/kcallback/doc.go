// Package kcallback enumerates the kernel-mode callback arrays EDR
// products register to observe process/thread/image-load events, and
// (pluggable future work) provides the surface to remove them.
//
// Technique: read the ntoskrnl callback arrays
// (PspCreateProcessNotifyRoutine, PspCreateThreadNotifyRoutine,
// PspLoadImageNotifyRoutine) via a caller-supplied KernelReader. When
// the KernelReader is backed by a driver-level primitive (BYOVD like
// RTCore64, GDRV, or a dedicated driver), the package can also report
// which routines are registered and by which signed driver.
//
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools —
// the kernel-mode analogue of userland EDR patching).
// Platform: Windows amd64
// Detection: Low when removal succeeds cleanly (the EDR simply stops
// getting callbacks and often reports itself as "running"). High
// during the BYOVD driver load — Win10/11 HVCI blocks unsigned
// drivers and the attested driver list is audited.
//
// v0.17.0 scope: enumeration only. Callers who plug in a real
// KernelReadWriter can experiment with Remove, but the API is marked
// Experimental until a driver chantier ships the arbitrary-kernel-
// memory-write primitive required to do so safely.
package kcallback
