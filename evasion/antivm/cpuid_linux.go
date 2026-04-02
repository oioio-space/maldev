//go:build linux

package antivm

import (
	"os"
	"strings"
)

// DetectCPUID checks /proc/cpuinfo for the "hypervisor" flag which the CPU
// sets when running under a hypervisor (via CPUID leaf 1, ECX bit 31).
// Returns true and a description if the flag is present.
func DetectCPUID() (bool, string) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false, ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "flags") {
			continue
		}
		if strings.Contains(line, "hypervisor") {
			return true, "CPUID hypervisor flag present"
		}
	}
	return false, ""
}
