// Package sleepmask provides encrypted sleep to defeat memory scanning.
//
// Technique: Encrypt payload memory regions during sleep intervals, making
// them invisible to periodic memory scanners that look for known shellcode
// patterns or PE headers in executable memory.
// MITRE ATT&CK: T1027 (Obfuscated Files or Information)
// Detection: Low -- VirtualProtect + XOR are hard to distinguish from
// legitimate application behavior.
// Platform: Windows.
//
// How it works. Before sleeping, each registered region's current page
// protection is captured (via VirtualProtect's old-protect out-param) and
// the region is downgraded to PAGE_READWRITE. The bytes are XOR-encrypted
// with a fresh 32-byte random key. The sleep itself uses either
// MethodNtDelay (Go's time.Sleep, which on Windows is implemented via
// NtWaitForSingleObject on a timer) or MethodBusyTrig (a CPU-burning
// trigonometric busy wait from evasion/timing, which defeats sandbox
// time-acceleration and hooked Sleep/NtDelayExecution). After waking,
// the region is XOR-decrypted and the original protection is restored.
// The XOR key is finally scrubbed via cleanup/memory.SecureZero.
//
// Why the RW downgrade matters. EDR memory scanners focus on executable
// pages (PAGE_EXECUTE_READ / PAGE_EXECUTE_READWRITE) because that's where
// shellcode lives. While masked, the region is non-executable AND
// XOR-scrambled, so a scan of executable pages turns up nothing that
// matches a shellcode signature. See TestSleepMaskE2E_DefeatsExecutablePageScanner
// for a concrete demonstration that runs a scanner concurrently.
//
// Limitations:
//   - The sleep mask code itself must remain executable (it cannot encrypt itself).
//   - Very short sleep intervals add VirtualProtect + XOR overhead that may be
//     detectable.
//   - The XOR key lives on the Go stack during the sleep; a targeted dump
//     could recover it.
//   - MethodNtDelay goes through Go's runtime scheduler, so Sleep hooks on
//     kernel32!Sleep will not see it, but NtWaitForSingleObject hooks will.
//     Use MethodBusyTrig to avoid scheduling-based waits entirely.
//
// Example:
//
//	mask := sleepmask.New(
//	    sleepmask.Region{Addr: shellcodeAddr, Size: shellcodeLen},
//	)
//	mask.Sleep(30 * time.Second) // region encrypted and RW during this time
package sleepmask
