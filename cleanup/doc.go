// Package cleanup is the umbrella for on-host artefact removal /
// anti-forensics primitives that run after an operation completes.
//
// Cleanup is split across sub-packages keyed by what is being
// scrubbed:
//
//   - [github.com/oioio-space/maldev/cleanup/memory] — zero
//     sensitive buffers in-process before free.
//   - [github.com/oioio-space/maldev/cleanup/timestomp] — reset NTFS
//     `$STANDARD_INFORMATION` timestamps.
//   - [github.com/oioio-space/maldev/cleanup/wipe] — multi-pass
//     overwrite-then-rename-then-delete.
//   - [github.com/oioio-space/maldev/cleanup/selfdelete] — delete the
//     running executable via NTFS-rename trick (`MoveFileEx` +
//     `MOVEFILE_DELAY_UNTIL_REBOOT` fallback).
//   - [github.com/oioio-space/maldev/cleanup/ads] — drop / read NTFS
//     Alternate Data Streams as transient staging.
//   - [github.com/oioio-space/maldev/cleanup/bsod] — controlled
//     `NtRaiseHardError` BSOD as a last-resort kill switch.
//   - [github.com/oioio-space/maldev/cleanup/service] — unregister
//     SCM service entries left by the implant.
//
// The umbrella package exports nothing — it carries only this
// doc.go. Import the sub-package matching the artefact you need to
// scrub.
//
// # MITRE ATT&CK
//
//   - T1070 (Indicator Removal on Host) — umbrella
//   - T1070.004 (File Deletion) — selfdelete, wipe
//   - T1070.006 (Timestomp) — timestomp
//   - T1564.004 (Hide Artifacts: NTFS File Attributes) — ads
//   - T1543.003 (service hiding) — service
//   - T1529 (System Shutdown/Reboot) — bsod
//
// # Detection level
//
// quiet (per-primitive baseline — see each sub-package for nuances)
//
// Most primitives are silent on disk-only telemetry but visible to
// EDR file-system minifilters that watch `DeleteFile`,
// `SetFileInformationByHandle`, and ADS writes. `bsod` is the
// outlier — `NtRaiseHardError` always emits a kernel crash dump.
//
// # Example
//
// See each sub-package `<name>_example_test.go` for runnable
// examples of each primitive.
//
// # See also
//
//   - docs/techniques/cleanup/README.md
//   - [github.com/oioio-space/maldev/evasion/sleepmask] — companion
//     in-process scrub between beacons (memory-only, not disk)
//
// [github.com/oioio-space/maldev/evasion/sleepmask]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/sleepmask
package cleanup
