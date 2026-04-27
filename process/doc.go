// Package process is the umbrella for cross-platform process
// enumeration / management, plus the Windows-specific
// process-tamper sub-tree.
//
// The package itself ships no exported symbols — implants and
// operator tools import the sub-package they need:
//
//   - process/enum — list and find running processes by name /
//     predicate (Windows + Linux).
//   - process/session — Windows session / desktop token
//     discovery and remote-process creation.
//   - process/tamper/fakecmd — overwrite the current process's
//     PEB CommandLine for argv0 spoofing.
//   - process/tamper/herpaderping — Process Herpaderping +
//     Process Ghosting (kernel image-section cache exploitation).
//   - process/tamper/hideprocess — patch
//     `NtQuerySystemInformation` in a target process to blind
//     it from enumeration.
//   - process/tamper/phant0m — terminate Event Log service
//     threads to suppress Windows Event Log writes.
//
// # MITRE ATT&CK
//
//   - T1057 (Process Discovery) — process/enum
//   - T1134.002 (Access Token Manipulation: Create Process with Token) — process/session
//   - T1036.005 (Masquerading: Match Legitimate Name or Location) — process/tamper/fakecmd
//   - T1055.013 (Process Doppelgänging) — process/tamper/herpaderping (related kernel-cache technique)
//   - T1564.001 (Hide Artifacts: Hidden Process) — process/tamper/hideprocess
//   - T1562.002 (Impair Defenses: Disable Windows Event Logging) — process/tamper/phant0m
//
// # Detection level
//
// Varies by sub-package. process/enum is invisible (standard
// OS APIs); process/session emits cross-session creation
// events; process/tamper/* range from quiet (fakecmd) to
// noisy (phant0m).
//
// # Example
//
// See [github.com/oioio-space/maldev/process/enum] and
// [github.com/oioio-space/maldev/process/tamper/herpaderping]
// for runnable examples.
//
// # See also
//
//   - docs/techniques/process/README.md
//   - [github.com/oioio-space/maldev/inject] — process/tamper/herpaderping is an alternative to inject for fresh-process delivery
//   - [github.com/oioio-space/maldev/credentials] — process/enum + process/session feed credential dumping pipelines
//
// [github.com/oioio-space/maldev/process/enum]: https://pkg.go.dev/github.com/oioio-space/maldev/process/enum
// [github.com/oioio-space/maldev/process/tamper/herpaderping]: https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/herpaderping
// [github.com/oioio-space/maldev/inject]: https://pkg.go.dev/github.com/oioio-space/maldev/inject
// [github.com/oioio-space/maldev/credentials]: https://pkg.go.dev/github.com/oioio-space/maldev/credentials
package process
