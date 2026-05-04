//go:build windows

// Package sleepmask encrypts the implant's payload memory while it
// sleeps so concurrent memory scanners cannot recover the original
// shellcode bytes or PE headers.
//
// Mask binds N regions, a Cipher (RC4 or AES-CTR), and a Strategy. Each
// Mask.Sleep call: snapshots the current page protection of every
// region, downgrades to PAGE_READWRITE, runs the cipher in place,
// invokes the chosen Strategy for the actual delay, decrypts on wake,
// and restores the original protection. The cipher key is scrubbed
// via [github.com/oioio-space/maldev/cleanup/memory.SecureZero] before
// the call returns.
//
// Strategies (Strategy interface):
//
//   - EkkoStrategy — full ROP chain à la `Cracked5pider/Ekko`.
//     Highest-leverage masking; uses CreateTimerQueueTimer / NtQueueApcThreadEx
//     to weave the mask sequence into a non-blocking wait.
//   - FoliageStrategy — APC-driven variant that schedules the mask
//     callback on a different thread while the implant blocks.
//   - InlineStrategy — straight-line encrypt-sleep-decrypt; suitable
//     for short delays where ROP overhead isn't worth it.
//   - RemoteInlineStrategy — masks regions in a different process.
//
// Ciphers: AESCTRCipher (32-byte key, fast on AESNI hosts) and RC4Cipher
// (16-byte key, no AESNI dependency).
//
// MultiRegionRotation rotates a fresh key per region per sleep — useful
// when one region is much hotter than another.
//
// # MITRE ATT&CK
//
//   - T1027 (Obfuscated Files or Information)
//
// # Detection level
//
// quiet
//
// VirtualProtect + XOR are high-volume legitimate calls. While masked,
// the regions are RW (not RX) and bytes are scrambled — most pattern-
// based scanners turn up nothing. ROP-based strategies (Ekko, Foliage)
// produce distinctive call-stack signatures that some EDRs catch.
//
// # Required privileges
//
// unprivileged. Mask operates on the calling process's own
// pages — `VirtualProtect` flips on own-process regions,
// AES/RC4 in-place over caller-supplied buffers,
// `CreateTimerQueueTimer` / `NtQueueApcThreadEx` against
// the calling process's own threads. No token bump.
// `RemoteInlineStrategy` requires
// `PROCESS_VM_OPERATION | PROCESS_VM_WRITE` on the target
// — same-user same-IL is unprivileged; protected targets
// need `SeDebugPrivilege` (admin).
//
// # Platform
//
// Windows-only (`//go:build windows`) and amd64-only
// (Ekko / Foliage ROP chains assume x64 unwind layout).
// The cipher pieces are stdlib `crypto/aes` + RC4 — those
// would port elsewhere; the strategies that thread them
// into the sleep would not.
//
// # Example
//
// See [ExampleMask_Sleep] and [ExampleMask_chain] in sleepmask_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/sleep-mask.md
//   - [github.com/oioio-space/maldev/cleanup/memory] — key scrubbing
//   - [github.com/oioio-space/maldev/recon/timing] — `MethodBusyTrig` for sandbox-bypass sleeps
//
// [github.com/oioio-space/maldev/cleanup/memory]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/memory
// [github.com/oioio-space/maldev/recon/timing]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/timing
package sleepmask
