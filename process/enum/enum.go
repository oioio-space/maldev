// Package enum provides cross-platform process enumeration.
package enum

// Process represents a running system process.
type Process struct {
	PID       uint32
	PPID      uint32
	Name      string
	SessionID uint32
}

// FindByName returns processes matching the given name.
func FindByName(name string) ([]Process, error) {
	procs, err := List()
	if err != nil {
		return nil, err
	}
	var result []Process
	for _, p := range procs {
		if p.Name == name {
			result = append(result, p)
		}
	}
	return result, nil
}
