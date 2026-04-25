// Package antivm provides cross-platform virtual machine and hypervisor
// detection techniques with configurable check dimensions.
//
// Technique: VM detection via registry keys, files, MAC prefixes, processes,
// CPUID/BIOS data, and DMI info.
// MITRE ATT&CK: T1497.001 (Virtualization/Sandbox Evasion: System Checks)
// Platform: Cross-platform (Windows and Linux)
// Detection: Low -- VM detection is common in legitimate software.
//
// Detected hypervisors: Hyper-V, Parallels, VirtualBox, VirtualPC, VMware,
// Xen, QEMU/KVM, Proxmox, Docker, and WSL.
//
// Use [Config] to control which vendors and detection dimensions are evaluated:
//
//	// Default: all vendors, all checks
//	name, err := antivm.Detect(antivm.DefaultConfig())
//
//	// Only check NIC and files for VMware
//	cfg := antivm.Config{
//	    Vendors: []antivm.Vendor{{Name: "VMware", Nic: []string{"00:0C:29"}}},
//	    Checks:  antivm.CheckNIC | antivm.CheckFiles,
//	}
//	name, err := antivm.Detect(cfg)
//
// Platform-specific implementations:
//   - Windows: checks registry keys, driver files, NIC MAC prefixes, processes, and BIOS product name
//   - Linux: checks DMI info in /sys/class/dmi/, files, NIC MAC prefixes, processes, and CPUID flags
package antivm
