//go:build linux

package injection

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ResolveTarget resolves a target (PID or process name) to a PID.
func ResolveTarget(target string) (int, error) {
	if target == "" {
		return 0, fmt.Errorf("target is empty")
	}

	if pid, err := strconv.Atoi(target); err == nil {
		if !ProcessExists(pid) {
			return 0, fmt.Errorf("PID %d does not exist", pid)
		}
		return pid, nil
	}

	pid, err := FindProcessByName(target)
	if err != nil {
		return 0, fmt.Errorf("failed to find process '%s': %w", target, err)
	}

	return pid, nil
}

// FindProcessByName finds the first process matching the given name.
func FindProcessByName(name string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		processName := strings.TrimSpace(string(data))

		if processName == name {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("process '%s' not found", name)
}

// ProcessExists checks whether a process with the given PID exists.
func ProcessExists(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// ListProcessesByName lists all PIDs matching the given name.
func ListProcessesByName(name string) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		processName := strings.TrimSpace(string(data))
		if processName == name {
			pids = append(pids, pid)
		}
	}

	if len(pids) == 0 {
		return nil, fmt.Errorf("no process found with name '%s'", name)
	}

	return pids, nil
}
