//go:build linux

// Package antivm provides virtual machine and hypervisor detection techniques.
package antivm

import (
	"net"
	"os"
	"strings"
)

// knownVMMACs contains MAC address prefixes associated with hypervisors.
var knownVMMACs = []string{
	"00:0c:29", "00:50:56", "00:05:69", // VMware
	"08:00:27", "52:54:00",              // VirtualBox / QEMU
	"00:15:5d",                          // Hyper-V
	"00:16:3e",                          // Xen
	"96:00:ff",                          // Proxmox
}

// DetectVM returns the detected hypervisor name, or empty string if none found.
func DetectVM() string {
	// Check DMI info
	for _, p := range []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor",
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.ToLower(strings.TrimSpace(string(data)))
		switch {
		case strings.Contains(s, "vmware"):
			return "VMware"
		case strings.Contains(s, "virtualbox") || strings.Contains(s, "vbox"):
			return "VirtualBox"
		case strings.Contains(s, "qemu") || strings.Contains(s, "kvm"):
			return "QEMU/KVM"
		case strings.Contains(s, "microsoft"):
			return "Hyper-V"
		case strings.Contains(s, "xen"):
			return "Xen"
		}
	}
	// Check MAC addresses
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		mac := strings.ToLower(iface.HardwareAddr.String())
		for _, prefix := range knownVMMACs {
			if strings.HasPrefix(mac, prefix) {
				return "VM (MAC: " + prefix + ")"
			}
		}
	}
	return ""
}

// IsRunningInVM returns true if any VM indicator is detected.
func IsRunningInVM() bool { return DetectVM() != "" }
