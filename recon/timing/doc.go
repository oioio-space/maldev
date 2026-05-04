// Package timing provides time-based evasion that defeats
// sandboxes which fast-forward `Sleep()` calls — sandboxes
// commonly hook `Sleep` / `WaitForSingleObject` to skip the
// delay and analyse what the implant does next.
//
// Two flavours, both cross-platform:
//
//   - [BusyWait] — burns CPU for a real wall-clock duration
//     by repeatedly comparing `time.Now()` to the deadline.
//     Sandboxes that fast-forward `Sleep` do not fast-forward
//     CPU-burn loops.
//   - [BusyWaitPrimality] / [BusyWaitPrimalityN] — burns CPU
//     via primality testing. Same wall-clock effect but the
//     CPU pattern doesn't pin one core at 100% in a tight
//     time-comparison loop, which behavioural sandboxes can
//     fingerprint.
//
// # MITRE ATT&CK
//
//   - T1497.003 (Virtualization/Sandbox Evasion: Time Based Evasion)
//
// # Detection level
//
// quiet
//
// CPU usage spikes are not typically alerted on in user
// processes. Some behavioural sandboxes flag long-running
// CPU-burn loops with no I/O as anomalous; the primality
// variant blends better with mathematical workloads.
//
// # Required privileges
//
// unprivileged. Pure `time.Now()` polling +
// stdlib `math/big.ProbablyPrime` arithmetic; no syscall,
// no token.
//
// # Platform
//
// Cross-platform. Stdlib `time` + `math/big`; no build
// tags.
//
// # Example
//
// See [ExampleBusyWait] in timing_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/timing.md
//   - [github.com/oioio-space/maldev/recon/sandbox] — orchestrator that uses timing
//   - [github.com/oioio-space/maldev/evasion/sleepmask] — pair for cleartext-payload-at-rest mitigation
//
// [github.com/oioio-space/maldev/recon/sandbox]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/sandbox
// [github.com/oioio-space/maldev/evasion/sleepmask]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/sleepmask
package timing
