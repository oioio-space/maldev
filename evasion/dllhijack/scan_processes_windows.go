//go:build windows

package dllhijack

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/oioio-space/maldev/pe/imports"
	"github.com/oioio-space/maldev/process/enum"
)

// ScanProcesses enumerates every running process the current token can
// open and emits a hijack Opportunity per (process, loadedModule) pair
// where a user-writable directory sits earlier in the DLL search order
// than where the module currently loads from.
//
// Unlike ScanServices, which parses STATIC PE imports, ScanProcesses
// reads the LIVE loaded-module list via CreateToolhelp32Snapshot — so
// DLLs loaded at runtime via LoadLibrary are covered too.
//
// Processes we cannot open (PPL, protected, other user's sessions)
// are silently skipped; enumeration continues.
func ScanProcesses() ([]Opportunity, error) {
	procs, err := enum.List()
	if err != nil {
		return nil, fmt.Errorf("dllhijack/processes: enum: %w", err)
	}

	var opps []Opportunity
	for _, p := range procs {
		if p.PID == 0 || p.PID == 4 {
			continue // System Idle Process / System
		}
		exePath, err := enum.ImagePath(p.PID)
		if err != nil || exePath == "" {
			continue
		}
		exeDir := filepath.Dir(exePath)

		mods, err := enum.Modules(p.PID)
		if err != nil || len(mods) == 0 {
			continue
		}
		seen := make(map[string]struct{}, len(mods))
		for _, m := range mods {
			// Skip the main exe; we care about DLL imports only.
			if strings.EqualFold(m.Path, exePath) {
				continue
			}
			name := strings.ToLower(m.Name)
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}

			hijackDir, resolvedDir := HijackPath(exeDir, m.Name)
			if hijackDir == "" {
				continue
			}
			opps = append(opps, Opportunity{
				Kind:         KindProcess,
				ID:           fmt.Sprintf("%d", p.PID),
				DisplayName:  p.Name,
				BinaryPath:   exePath,
				HijackedDLL:  m.Name,
				HijackedPath: filepath.Join(hijackDir, m.Name),
				ResolvedDLL:  filepath.Join(resolvedDir, m.Name),
				SearchDir:    hijackDir,
				Writable:     true,
				Reason:       "loaded module " + m.Name + " resolves from writable " + hijackDir + " before " + resolvedDir,
			})
		}
	}
	return opps, nil
}

// ScanScheduledTasks enumerates registered scheduled tasks, fetches each
// task's exec-action binary paths via the COM ITaskService interface,
// and emits Opportunity rows for (task, binary, importedDLL) triples
// whose search order exposes a writable dir.
//
// Only TASK_ACTION_EXEC actions are analyzed. Non-exec actions (COM,
// email, message) have no binary to hijack.
//
// Requires no elevation to enumerate; writability probe runs as the
// current token.
func ScanScheduledTasks() ([]Opportunity, error) {
	tasks, err := scanTasks()
	if err != nil {
		return nil, fmt.Errorf("dllhijack/tasks: enumerate tasks: %w", err)
	}

	var opps []Opportunity
	for _, t := range tasks {
		for _, binPath := range t.actions {
			binPath = expandEnvVars(binPath)
			if !fileExists(binPath) {
				continue
			}
			exeDir := filepath.Dir(binPath)

			imps, err := imports.List(binPath)
			if err != nil {
				continue
			}
			seen := make(map[string]struct{}, len(imps))
			for _, imp := range imps {
				dllName := strings.ToLower(imp.DLL)
				if _, dup := seen[dllName]; dup {
					continue
				}
				seen[dllName] = struct{}{}

				hijackDir, resolvedDir := HijackPath(exeDir, imp.DLL)
				if hijackDir == "" {
					continue
				}
				opps = append(opps, Opportunity{
					Kind:         KindScheduledTask,
					ID:           t.path,
					DisplayName:  t.name,
					BinaryPath:   binPath,
					HijackedDLL:  imp.DLL,
					HijackedPath: filepath.Join(hijackDir, imp.DLL),
					ResolvedDLL:  filepath.Join(resolvedDir, imp.DLL),
					SearchDir:    hijackDir,
					Writable:     true,
					Reason:       "task action " + filepath.Base(binPath) + " imports " + imp.DLL + " resolvable from writable " + hijackDir,
				})
			}
		}
	}
	return opps, nil
}

// ScanAll runs ScanServices + ScanProcesses + ScanScheduledTasks and
// concatenates the results. Errors from any individual scanner are
// wrapped but do not abort the others.
func ScanAll() ([]Opportunity, error) {
	var all []Opportunity
	var errs []string
	if opps, err := ScanServices(); err != nil {
		errs = append(errs, "services: "+err.Error())
	} else {
		all = append(all, opps...)
	}
	if opps, err := ScanProcesses(); err != nil {
		errs = append(errs, "processes: "+err.Error())
	} else {
		all = append(all, opps...)
	}
	if opps, err := ScanScheduledTasks(); err != nil {
		errs = append(errs, "tasks: "+err.Error())
	} else {
		all = append(all, opps...)
	}
	if len(errs) > 0 {
		return all, fmt.Errorf("dllhijack/ScanAll: partial failures: %s", strings.Join(errs, "; "))
	}
	return all, nil
}
