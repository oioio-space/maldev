//go:build windows

package dllhijack

import "github.com/oioio-space/maldev/persistence/scheduler"

type taskInfo struct {
	name    string
	path    string
	actions []string
}

// scanTasks is a thin wrapper around the persistence/scheduler package
// that returns (name, path, actions) triples for every registered task.
// Tasks whose Actions() call fails (permission denied, etc.) are
// silently skipped.
func scanTasks() ([]taskInfo, error) {
	tasks, err := scheduler.List()
	if err != nil {
		return nil, err
	}
	out := make([]taskInfo, 0, len(tasks))
	for _, t := range tasks {
		acts, err := scheduler.Actions(t.Path)
		if err != nil {
			continue
		}
		out = append(out, taskInfo{name: t.Name, path: t.Path, actions: acts})
	}
	return out, nil
}
