// Package antivm provides cross-platform virtual machine and hypervisor
// detection techniques.
//
// Technique: VM detection via registry keys, files, MAC prefixes, and DMI data.
// MITRE ATT&CK: T1497.001 (Virtualization/Sandbox Evasion: System Checks)
// Platform: Cross-platform (Windows and Linux)
// Detection: Low -- VM detection is common in legitimate software.
//
// Detected hypervisors: Hyper-V, Parallels, VirtualBox, VirtualPC, VMware,
// Xen, QEMU/KVM, and Proxmox.
//
// Platform-specific implementations:
//   - Windows: checks registry keys, driver files, NIC MAC prefixes, and processes
//   - Linux: checks DMI info in /sys/class/dmi/ and NIC MAC prefixes
package antivm
