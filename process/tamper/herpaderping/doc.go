// Package herpaderping implements the Process Herpaderping technique.
//
// # How It Works
//
// Process Herpaderping exploits the kernel's image-section caching behaviour
// during process creation. When a process is created, the sequence is:
//
//  1. NtCreateSection(SEC_IMAGE) — the kernel maps and caches the PE image
//     into an immutable section object. This cache persists independently of
//     the file on disk.
//  2. NtCreateProcessEx — a new process object is created from the section.
//     At this point the process exists in kernel memory but has no threads.
//  3. File overwrite — the backing file on disk is replaced with decoy content
//     (a legitimate PE such as svchost.exe, or random bytes).
//  4. NtCreateThreadEx — the initial thread is created. This is the moment
//     that triggers EDR/AV security callbacks (PsSetCreateThreadNotifyRoutine).
//     When the callback fires, any attempt to read the file backing the process
//     returns the decoy, not the original payload.
//
// The running process executes the original payload from the kernel image
// cache. File-based inspection — whether by EDR, Task Manager, or forensic
// tools — sees only the decoy.
//
// # Comparison with Related Techniques
//
// Process Hollowing (T1055.012): writes shellcode or a new PE into an already
// running (suspended) process via WriteProcessMemory. The on-disk image of the
// host process is never modified; memory forensics still recovers the injected
// payload. Herpaderping operates at a lower level — the deception is in the
// kernel section cache, not in user-space memory.
//
// Process Ghosting (ModeGhosting, Gabriel Landau 2021): creates a
// delete-pending file, maps it as SEC_IMAGE, then closes the handle to
// let the file deletion complete BEFORE creating the process. The file
// never exists at the time of thread creation. This package implements
// both variants; ModeGhosting was confirmed to bypass Win11 24H2 by
// hasherezade (Jan 2025) on the early-26100 build, but our own
// measurement against build 26200 (Win11 25H2 / late-26100 cumulative
// updates may apply equally) saw NtCreateProcessEx return
// STATUS_NOT_SUPPORTED for ModeGhosting too. The package therefore
// treats every Win11 build ≥ 26100 as "both modes blocked" out of an
// abundance of caution; operators with verified-working 26100 builds
// can drop the test skip locally. Both modes exploit the same kernel
// caching primitive but at different lifecycle stages.
//
// # Advantages
//
//   - The file on disk always shows benign content when inspected by EDR or AV.
//   - No WriteProcessMemory calls on the host process — nothing is injected into
//     an existing process, so cross-process memory anomalies are not triggered.
//   - Compatible with signed decoy binaries (e.g. system32 executables), which
//     appear as the process image to tools that rely on authenticode verification.
//
// # Limitations
//
//   - Requires write access to the target path (the file that is overwritten).
//   - Does not work on read-only media or when the target path is locked by
//     another process.
//   - The process image path in the PEB points to the target file, which now
//     contains the decoy. Resolving the image path by re-reading the file will
//     therefore return the decoy, but in-memory reconstruction is still possible.
//   - Requires Windows 10 or later (NtCreateProcessEx behaviour differs on
//     older versions).
//   - Win11 26100+ (24H2 / 25H2) hardens NtCreateProcessEx against
//     section-from-tampered-or-deleted-file. Both ModeHerpaderping and
//     ModeGhosting return STATUS_NOT_SUPPORTED on those builds. The
//     primitives still ship for Win10 + Win11 < 26100; new bypass research
//     is required for 26100+ targets (Process Doppelgänging via
//     transactions, PE-from-memory loaders are candidate replacements).
//
// # Detection
//
// Sysmon Event ID 25 (ProcessTampering) fires when the kernel detects that a
// process's mapped image does not match the file on disk. This is the primary
// detection signal for Herpaderping. Advanced EDRs also watch for:
//
//   - NtCreateSection(SEC_IMAGE) followed by a file write on the same handle
//     before NtCreateThreadEx.
//   - Processes whose authenticode chain resolves to the decoy PE but whose
//     memory layout matches a different executable.
//
// Technique: Process Herpaderping
// MITRE ATT&CK: T1055 (Process Injection — defense evasion via process tampering)
// Detection: Medium — Sysmon Event ID 25 (ProcessTampering), advanced EDR
// Platform: Windows only (x64)
//
// Reference: https://jxy-s.github.io/herpaderping/
//
// # Usage
//
// Basic execution with a decoy:
//
//	err := herpaderping.Run(herpaderping.Config{
//	    PayloadPath: "payload.exe",
//	    TargetPath:  `C:\Windows\Temp\legit.exe`,
//	    DecoyPath:   `C:\Windows\System32\svchost.exe`,
//	})
//
// Execution with random-byte decoy (no real PE needed):
//
//	err := herpaderping.Run(herpaderping.Config{
//	    PayloadPath: "payload.exe",
//	    TargetPath:  `C:\Windows\Temp\legit.exe`,
//	    // DecoyPath omitted — target is overwritten with random bytes
//	})
//
// Auto-generated temp path (no TargetPath needed):
//
//	err := herpaderping.Run(herpaderping.Config{
//	    PayloadPath: "payload.exe",
//	    DecoyPath:   `C:\Windows\System32\notepad.exe`,
//	    // TargetPath omitted — os.CreateTemp is used automatically
//	})
//
// Process Ghosting (recommended on Win11 24H2 — file unlinked before
// process creation, no on-disk artefact at all):
//
//	err := herpaderping.Run(herpaderping.Config{
//	    Mode:        herpaderping.ModeGhosting,
//	    PayloadPath: "payload.exe",
//	    TargetPath:  `C:\Windows\Temp\nohost.exe`,
//	    // DecoyPath ignored — the file is unlinked, not overwritten
//	})
//
// Via the composable evasion.Technique interface:
//
//	techniques := []evasion.Technique{
//	    amsi.ScanBufferPatch(),
//	    herpaderping.Technique(herpaderping.Config{
//	        PayloadPath: "implant.exe",
//	        TargetPath:  `C:\Temp\legit.exe`,
//	        DecoyPath:   `C:\Windows\System32\svchost.exe`,
//	    }),
//	}
//	evasion.ApplyAll(techniques, nil)
package herpaderping
