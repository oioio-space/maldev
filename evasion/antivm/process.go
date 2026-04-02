package antivm

import (
	"strings"

	"github.com/oioio-space/maldev/process/enum"
)

// DetectProcess returns true if any running process name contains one of the
// given substrings (case-insensitive). Also returns the matched process name.
//
// Example:
//
//	found, name, err := antivm.DetectProcess([]string{"vmtoolsd", "vboxtray"})
//	if found {
//	    fmt.Printf("VM process detected: %s\n", name)
//	}
func DetectProcess(procNames []string) (bool, string, error) {
	procs, err := enum.List()
	if err != nil {
		return false, "", err
	}
	for _, p := range procs {
		lower := strings.ToLower(p.Name)
		for _, target := range procNames {
			if strings.Contains(lower, strings.ToLower(target)) {
				return true, p.Name, nil
			}
		}
	}
	return false, "", nil
}
