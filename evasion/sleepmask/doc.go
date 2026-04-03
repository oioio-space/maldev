// Package sleepmask provides encrypted sleep to defeat memory scanning.
//
// Technique: Encrypt payload memory regions during sleep intervals, making
// them invisible to periodic memory scanners that look for known shellcode
// patterns or PE headers in executable memory.
// MITRE ATT&CK: T1027 (Obfuscated Files or Information)
// Detection: Low — memory permissions change and XOR encryption are hard to
// distinguish from legitimate application behavior.
// Platform: Windows.
//
// How it works: Before sleeping, all registered memory regions are XOR-encrypted
// with a random key and their page permissions are downgraded from
// PAGE_EXECUTE_READ to PAGE_READWRITE. The sleep itself uses either
// NtDelayExecution (via Caller for EDR bypass) or evasion/timing.BusyWaitTrig
// (for sandbox evasion). After waking, regions are decrypted and restored
// to PAGE_EXECUTE_READ.
//
// Limitations:
//   - The sleep mask code itself remains in executable memory (it cannot encrypt itself).
//   - Very short sleep intervals add VirtualProtect overhead.
//   - The XOR key is in the Go stack during sleep — a targeted memory dump could find it.
//
// Example:
//
//	mask := sleepmask.New(
//	    sleepmask.Region{Addr: shellcodeAddr, Size: shellcodeLen},
//	)
//	mask.Sleep(30 * time.Second) // encrypted during this time
package sleepmask
