//go:build linux

package enum

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func List() ([]Process, error) {
	dirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, err
	}
	var procs []Process
	for _, dir := range dirs {
		pid, err := strconv.ParseUint(filepath.Base(dir), 10, 32)
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil {
			continue
		}
		status, _ := os.ReadFile(filepath.Join(dir, "status"))
		ppid := uint32(0)
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					v, _ := strconv.ParseUint(fields[1], 10, 32)
					ppid = uint32(v)
				}
			}
		}
		procs = append(procs, Process{
			PID:  uint32(pid),
			PPID: ppid,
			Name: strings.TrimSpace(string(comm)),
		})
	}
	return procs, nil
}
