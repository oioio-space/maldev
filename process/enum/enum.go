// Package enum provides cross-platform process enumeration.
package enum

import (
	"fmt"
	"strings"
)

// Process represents a running system process.
type Process struct {
	PID       uint32
	PPID      uint32
	Name      string
	SessionID uint32
}

// FindProcess returns the first process matching the predicate.
func FindProcess(pred func(name string, pid, ppid uint32) bool) (*Process, error) {
	procs, err := List()
	if err != nil {
		return nil, err
	}
	for _, p := range procs {
		if pred(p.Name, p.PID, p.PPID) {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("no process matching predicate")
}

// FindByName returns processes matching the given name (case-insensitive).
func FindByName(name string) ([]Process, error) {
	procs, err := List()
	if err != nil {
		return nil, err
	}
	var result []Process
	for _, p := range procs {
		if strings.EqualFold(p.Name, name) {
			result = append(result, p)
		}
	}
	return result, nil
}
