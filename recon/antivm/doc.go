// Package antivm detects virtual machines and hypervisors via
// configurable check dimensions: registry keys, files, MAC
// prefixes, processes, CPUID/BIOS, and DMI info.
//
// Detected hypervisors: Hyper-V, Parallels, VirtualBox,
// VirtualPC, VMware, Xen, QEMU/KVM, Proxmox, Docker, WSL.
//
// [Config] selects which vendors and dimensions to evaluate;
// [DefaultConfig] enables all. [Detect] returns the first
// matching vendor name; [DetectAll] returns every match.
// Dimension-specific helpers ([DetectNic], [DetectFiles],
// [DetectDMI]) let callers compose their own pipelines.
//
// # MITRE ATT&CK
//
//   - T1497.001 (Virtualization/Sandbox Evasion: System Checks)
//
// # Detection level
//
// quiet
//
// VM detection is universally common in legitimate software
// (DRM, anti-piracy, performance-tuning) — no defensive tool
// flags it on its own. Combined with subsequent suspicious
// actions an EDR may correlate.
//
// # Example
//
// See [ExampleDetect] in antivm_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/anti-analysis.md
//   - [github.com/oioio-space/maldev/recon/sandbox] — multi-factor orchestrator
//   - [github.com/oioio-space/maldev/recon/antidebug] — sibling debugger detection
//
// [github.com/oioio-space/maldev/recon/sandbox]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/sandbox
// [github.com/oioio-space/maldev/recon/antidebug]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/antidebug
package antivm
