//go:build linux

// Package antivm provides virtual machine and hypervisor detection techniques.
package antivm

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Vendor represents a hypervisor vendor with its characteristic indicators:
// files, NIC MAC prefixes, and process names.
type Vendor struct {
	Name  string
	Files []string
	Nic   []string
	Proc  []string
}

// DefaultVendors is the built-in list of known hypervisor indicators for Linux.
var DefaultVendors = []Vendor{
	{
		Name:  "VMware",
		Files: []string{"/usr/bin/vmtoolsd"},
		Proc:  []string{"vmtoolsd", "vmwaretray"},
		Nic:   []string{"00:0C:29", "00:50:56"},
	},
	{
		Name:  "VirtualBox",
		Files: []string{"/usr/bin/VBoxClient"},
		Proc:  []string{"vboxservice", "vboxtray", "VBoxClient"},
		Nic:   []string{"08:00:27"},
	},
	{
		Name: "QEMU/KVM",
		Proc: []string{"qemu-ga"},
		Nic:  []string{"52:54:00"},
	},
	{
		Name: "Hyper-V",
		Proc: []string{"hv_kvp_daemon"},
		Nic:  []string{"00:15:5D"},
	},
	{
		Name: "Xen",
		Proc: []string{"xenservice"},
		Nic:  []string{"00:16:3E"},
	},
	{
		Name:  "Docker",
		Files: []string{"/.dockerenv", "/run/.containerenv"},
	},
	{
		Name:  "WSL",
		Files: []string{"/proc/sys/fs/binfmt_misc/WSLInterop"},
	},
}

// DetectNic returns true if any network interface has a MAC address matching
// one of the given prefixes. Also returns the matched MAC string.
func DetectNic(macPrefixes []string) (bool, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, "", err
	}
	for _, iface := range ifaces {
		mac := iface.HardwareAddr.String()
		for _, prefix := range macPrefixes {
			if strings.HasPrefix(strings.ToLower(mac), strings.ToLower(prefix)) {
				return true, mac, nil
			}
		}
	}
	return false, "", nil
}

// DetectFiles returns true if any of the given file paths exists on disk.
// Also returns the first detected path.
func DetectFiles(files []string) (bool, string) {
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			return true, f
		}
	}
	return false, ""
}

// dmiPaths are sysfs files containing hypervisor identity strings set by the
// host firmware (SMBIOS/DMI data).
var dmiPaths = []string{
	"/sys/class/dmi/id/product_name",
	"/sys/class/dmi/id/sys_vendor",
	"/sys/class/dmi/id/board_vendor",
}

// DetectDMI reads DMI identity files and returns the detected hypervisor name.
// Returns empty string if no known hypervisor is identified.
func DetectDMI() (bool, string) {
	for _, p := range dmiPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.ToLower(strings.TrimSpace(string(data)))
		switch {
		case strings.Contains(s, "vmware"):
			return true, "VMware"
		case strings.Contains(s, "virtualbox") || strings.Contains(s, "vbox"):
			return true, "VirtualBox"
		case strings.Contains(s, "qemu") || strings.Contains(s, "kvm"):
			return true, "QEMU/KVM"
		case strings.Contains(s, "microsoft"):
			return true, "Hyper-V"
		case strings.Contains(s, "xen"):
			return true, "Xen"
		case strings.Contains(s, "parallels"):
			return true, "Parallels"
		}
	}
	return false, ""
}

// Detect checks vendors from the given Config and returns the first detected
// vendor name and nil error. Returns empty string if no vendor is detected.
// CheckRegistry is ignored on Linux (no registry).
func Detect(cfg Config) (string, error) {
	checks := cfg.checks()

	// DMI check first -- fast and reliable on Linux.
	if found, name := DetectDMI(); found {
		return name, nil
	}

	for _, vendor := range cfg.vendors() {
		if checks&CheckFiles != 0 && len(vendor.Files) > 0 {
			if found, _ := DetectFiles(vendor.Files); found {
				return vendor.Name, nil
			}
		}
		if checks&CheckNIC != 0 && len(vendor.Nic) > 0 {
			if found, _, err := DetectNic(vendor.Nic); err != nil {
				return "", fmt.Errorf("NIC check: %w", err)
			} else if found {
				return vendor.Name, nil
			}
		}
		if checks&CheckProcess != 0 && len(vendor.Proc) > 0 {
			if found, _, err := DetectProcess(vendor.Proc); err != nil {
				return "", fmt.Errorf("process check: %w", err)
			} else if found {
				return vendor.Name, nil
			}
		}
	}
	if checks&CheckCPUID != 0 {
		if found, _ := DetectCPUID(); found {
			return "VM (CPUID)", nil
		}
	}
	return "", nil
}

// DetectAll checks all vendors from the given Config and returns every
// detected vendor name. Unlike Detect it does not short-circuit.
func DetectAll(cfg Config) ([]string, error) {
	checks := cfg.checks()
	seen := make(map[string]bool)
	var results []string

	// DMI check first.
	if found, name := DetectDMI(); found {
		seen[name] = true
		results = append(results, name)
	}

	for _, vendor := range cfg.vendors() {
		if seen[vendor.Name] {
			continue
		}
		if checks&CheckFiles != 0 && len(vendor.Files) > 0 {
			if found, _ := DetectFiles(vendor.Files); found {
				seen[vendor.Name] = true
				results = append(results, vendor.Name)
				continue
			}
		}
		if checks&CheckNIC != 0 && len(vendor.Nic) > 0 {
			if found, _, err := DetectNic(vendor.Nic); err != nil {
				return results, fmt.Errorf("NIC check: %w", err)
			} else if found {
				seen[vendor.Name] = true
				results = append(results, vendor.Name)
				continue
			}
		}
		if checks&CheckProcess != 0 && len(vendor.Proc) > 0 {
			if found, _, err := DetectProcess(vendor.Proc); err != nil {
				return results, fmt.Errorf("process check: %w", err)
			} else if found {
				seen[vendor.Name] = true
				results = append(results, vendor.Name)
				continue
			}
		}
	}
	if checks&CheckCPUID != 0 {
		if found, _ := DetectCPUID(); found && !seen["VM (CPUID)"] {
			results = append(results, "VM (CPUID)")
		}
	}
	return results, nil
}

// DetectVM checks the DefaultVendors list and returns the first detected
// vendor name, or empty string if none is found.
func DetectVM() string {
	r, _ := Detect(DefaultConfig())
	return r
}

// IsRunningInVM returns true if any VM indicator is detected.
func IsRunningInVM() bool { return DetectVM() != "" }
