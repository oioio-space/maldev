//go:build windows

package antivm

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// hypervisorKeywords maps known hypervisor product-name substrings.
var hypervisorKeywords = []string{
	"vmware", "virtualbox", "kvm", "qemu", "xen", "hyper-v", "parallels",
}

// DetectCPUID reads the BIOS SystemProductName from the Windows registry and
// checks it against known hypervisor keywords. This is the Windows equivalent
// of checking the CPUID hypervisor bit -- the BIOS product name is set by the
// hypervisor and is a reliable indicator.
func DetectCPUID() (bool, string) {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\BIOS`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return false, ""
	}
	defer k.Close()

	val, _, err := k.GetStringValue("SystemProductName")
	if err != nil {
		return false, ""
	}
	lower := strings.ToLower(val)
	for _, kw := range hypervisorKeywords {
		if strings.Contains(lower, kw) {
			return true, "BIOS SystemProductName: " + val
		}
	}
	return false, ""
}
