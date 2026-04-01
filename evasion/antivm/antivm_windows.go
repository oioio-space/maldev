//go:build windows

// Package antivm provides virtual machine and hypervisor detection techniques.
package antivm

import (
	"net"
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RegKey represents a registry key with an optional expected value.
type RegKey struct {
	Hive          registry.Key
	Path          string
	ExpectedValue string
}

// Vendor represents a hypervisor vendor with its characteristic indicators:
// registry keys, files, NIC MAC prefixes, and process name substrings.
type Vendor struct {
	Name  string
	Keys  []RegKey
	Files []string
	Nic   []string
	Proc  []string
}

// DefaultVendors is the built-in list of known hypervisor indicators covering
// Hyper-V, Parallels, VirtualBox, VirtualPC, VMware, Xen, QEMU, and Proxmox.
var DefaultVendors = []Vendor{
	{
		Name: "Hyper-V",
		Keys: []RegKey{
			{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Hyper-V`},
			{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\VirtualMachine`},
			{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`},
		},
		Nic: []string{`00:15:5D`},
	},
	{
		Name: "Parallels",
		Keys: []RegKey{
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AB8*`},
		},
		Files: []string{
			`c:\windows\system32\drivers\prleth.sys`,
			`c:\windows\system32\drivers\prlfs.sys`,
			`c:\windows\system32\drivers\prlmouse.sys`,
			`c:\windows\system32\drivers\prlvideo.sys`,
			`c:\windows\system32\drivers\prltime.sys`,
			`c:\windows\system32\drivers\prl_pv32.sys`,
			`c:\windows\system32\drivers\prl_paravirt_32.sys`,
		},
		Nic:  []string{`00:1C:42`},
		Proc: []string{`prl_cc`, `prl_tools`},
	},
	{
		Name: "VirtualBox",
		Keys: []RegKey{
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE*`},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\ACPI\DSDT\VBOX__`},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\ACPI\FADT\VBOX__`},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\ACPI\RSDT\VBOX__`},
			{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Oracle\VirtualBox Guest Additions`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\VBoxGuest`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\VBoxMouse`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\VBoxService`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\VBoxSF`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\VBoxVideo`},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier`, ExpectedValue: "VBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier`, ExpectedValue: "VBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier`, ExpectedValue: "VBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\Description\System\SystemBiosVersion`, ExpectedValue: "VBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\Description\System\VideoBiosVersion`, ExpectedValue: "VIRTUALBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\Description\System\BIOS\SystemProductName`, ExpectedValue: "VIRTUAL"},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\Disk\Enum\DeviceDesc`, ExpectedValue: "VBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\Disk\Enum\FriendlyName`, ExpectedValue: "VBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet002\Services\Disk\Enum\DeviceDesc`, ExpectedValue: "VBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet002\Services\Disk\Enum\FriendlyName`, ExpectedValue: "VBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet003\Services\Disk\Enum\DeviceDesc`, ExpectedValue: "VBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet003\Services\Disk\Enum\FriendlyName`, ExpectedValue: "VBOX"},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Control\SystemInformation\SystemProductName`, ExpectedValue: "VIRTUAL"},
		},
		Files: []string{
			`c:\windows\system32\drivers\VBoxMouse.sys`,
			`c:\windows\system32\drivers\VBoxGuest.sys`,
			`c:\windows\system32\drivers\VBoxSF.sys`,
			`c:\windows\system32\drivers\VBoxVideo.sys`,
			`c:\windows\system32\vboxdisp.dll`,
			`c:\windows\system32\vboxhook.dll`,
			`c:\windows\system32\vboxmrxnp.dll`,
			`c:\windows\system32\vboxogl.dll`,
			`c:\windows\system32\vboxoglarrayspu.dll`,
			`c:\windows\system32\vboxoglcrutil.dll`,
			`c:\windows\system32\vboxoglerrorspu.dll`,
			`c:\windows\system32\vboxoglfeedbackspu.dll`,
			`c:\windows\system32\vboxoglpackspu.dll`,
			`c:\windows\system32\vboxoglpassthroughspu.dll`,
			`c:\windows\system32\vboxservice.exe`,
			`c:\windows\system32\vboxtray.exe`,
			`c:\windows\system32\VBoxControl.exe`,
		},
		Nic:  []string{`08:00:27`, `52:54:00`, `00:21:F6`, `00:14:4F`, `00:0F:4B`},
		Proc: []string{`vbox`},
	},
	{
		Name: "VirtualPC",
		Keys: []RegKey{
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Enum\PCI\VEN_5333*`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\vpcbus`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\vpc-s3`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\vpcuhub`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\msvmmouf`},
		},
		Files: []string{
			`c:\windows\system32\drivers\vmsrvc.sys`,
			`c:\windows\system32\drivers\vpc-s3.sys`,
		},
		Nic:  []string{`00:03:FF`},
		Proc: []string{`vmsrvc`, `vmusrvc`},
	},
	{
		Name: "VMware",
		Keys: []RegKey{
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD*`},
			{Hive: registry.CURRENT_USER, Path: `SOFTWARE\VMware, Inc.\VMware Tools`},
			{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\VMware, Inc.\VMware Tools`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\vmdebug`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\vmmouse`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\VMTools`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\VMMEMCTL`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\vmware`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\vmci`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\vmx86`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_IDE_CD*`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_SATA_CD*`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_IDE_Hard_Drive*`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_SATA_Hard_Drive*`},
		},
		Files: []string{
			`c:\windows\system32\drivers\vmmouse.sys`,
			`c:\windows\system32\drivers\vmnet.sys`,
			`c:\windows\system32\drivers\vmxnet.sys`,
			`c:\windows\system32\drivers\vmhgfs.sys`,
			`c:\windows\system32\drivers\vmx86.sys`,
			`c:\windows\system32\drivers\hgfs.sys`,
		},
		Nic:  []string{`00:0C:29`, `00:1C:14`, `00:50:56`, `00:05:69`},
		Proc: []string{`vmware`, `vmtools`},
	},
	{
		Name: "Xen",
		Keys: []RegKey{
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\ACPI\DSDT\xen`},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\ACPI\FADT\xen`},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\ACPI\RSDT\xen`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\xenevtchn`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\xennet`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\xennet6`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\xensvc`},
			{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\ControlSet001\Services\xenvdb`},
		},
		Nic:  []string{`00:16:3E`},
		Proc: []string{`xenservice`},
	},
	{
		Name: "QEMU",
		Keys: []RegKey{
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier`, ExpectedValue: "QEMU"},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\Description\System\SystemBiosVersion`, ExpectedValue: "QEMU"},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\Description\System\VideoBiosVersion`, ExpectedValue: "QEMU"},
			{Hive: registry.LOCAL_MACHINE, Path: `HARDWARE\Description\System\BIOS\SystemManufacturer`, ExpectedValue: "QEMU"},
		},
	},
	{
		Name: "Proxmox",
		Nic:  []string{`96:00:FF`},
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
			if strings.Contains(strings.ToLower(mac), strings.ToLower(prefix)) {
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

// splitRegPath splits a registry path like "A\B\C\ValueName" into ("A\B\C", "ValueName").
func splitRegPath(p string) (keyPath, name string) {
	i := strings.LastIndex(p, `\`)
	if i < 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}

// DetectRegKey returns true if any of the given registry keys is present.
// Keys with ExpectedValue check the value content; keys ending in '*' check
// sub-key name prefixes; all others check key existence only.
func DetectRegKey(keys []RegKey) (bool, RegKey, error) {
	for _, k := range keys {
		if k.ExpectedValue != "" {
			kPath, kName := splitRegPath(k.Path)
			h, err := registry.OpenKey(k.Hive, kPath, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			val, _, err := h.GetStringValue(kName)
			h.Close()
			if err != nil {
				continue
			}
			if strings.Contains(val, k.ExpectedValue) {
				return true, k, nil
			}
			continue
		}

		kPath := k.Path
		kSubPrefix := ""
		if strings.HasSuffix(kPath, "*") {
			kPath = kPath[:len(kPath)-1]
			kPath, kSubPrefix = splitRegPath(kPath)
		}

		h, err := registry.OpenKey(k.Hive, kPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		if kSubPrefix != "" {
			subs, err := h.ReadSubKeyNames(0)
			h.Close()
			if err != nil {
				continue
			}
			for _, sub := range subs {
				if strings.HasPrefix(sub, kSubPrefix) {
					return true, k, nil
				}
			}
		} else {
			h.Close()
			return true, k, nil
		}
	}
	return false, RegKey{}, nil
}

// DetectVM checks the DefaultVendors list and returns the first detected
// vendor name, or empty string if none is found.
func DetectVM() string {
	for _, vendor := range DefaultVendors {
		if found, _ := DetectFiles(vendor.Files); found {
			return vendor.Name
		}
		if found, _, _ := DetectRegKey(vendor.Keys); found {
			return vendor.Name
		}
		if found, _, _ := DetectNic(vendor.Nic); found {
			return vendor.Name
		}
	}
	return ""
}

// IsRunningInVM returns true if any VM indicator from DefaultVendors is detected.
func IsRunningInVM() bool { return DetectVM() != "" }
