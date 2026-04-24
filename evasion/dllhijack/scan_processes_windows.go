//go:build windows

package dllhijack

import (
	"fmt"
	"path/filepath"
	"strings"

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
// ScanProcesses: opts is accepted for API symmetry with other scanners
// but the Opener is unused — this path reads LIVE loaded modules via
// Toolhelp32, not PE files from disk, so there is no file-read surface
// to reroute.
func ScanProcesses(opts ...ScanOpts) ([]Opportunity, error) {
	_ = firstOpts(opts)
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
		dllNames := make([]string, 0, len(mods))
		for _, m := range mods {
			// Skip the main exe; we care about DLL imports only.
			if strings.EqualFold(m.Path, exePath) {
				continue
			}
			dllNames = append(dllNames, m.Name)
		}
		opps = append(opps, emitOppsForDLLs(
			exePath, exeDir, KindProcess, fmt.Sprintf("%d", p.PID), p.Name, dllNames,
			func(dll, hijackDir, resolvedDir string) string {
				return "loaded module " + dll + " resolves from writable " + hijackDir + " before " + resolvedDir
			},
			nil,
		)...)
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
func ScanScheduledTasks(opts ...ScanOpts) ([]Opportunity, error) {
	o := firstOpts(opts)
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

			imps, err := readImports(binPath, o.Opener)
			if err != nil {
				continue
			}
			dllNames := make([]string, 0, len(imps))
			for _, imp := range imps {
				dllNames = append(dllNames, imp.DLL)
			}
			actionBase := filepath.Base(binPath)
			opps = append(opps, emitOppsForDLLs(
				binPath, exeDir, KindScheduledTask, t.path, t.name, dllNames,
				func(dll, hijackDir, _ string) string {
					return "task action " + actionBase + " imports " + dll + " resolvable from writable " + hijackDir
				},
				nil,
			)...)
		}
	}
	return opps, nil
}

// ScanAll runs ScanServices + ScanProcesses + ScanScheduledTasks +
// ScanAutoElevate and concatenates the results. Errors from any
// individual scanner are wrapped but do not abort the others.
func ScanAll(opts ...ScanOpts) ([]Opportunity, error) {
	var all []Opportunity
	var errs []string
	if opps, err := ScanServices(opts...); err != nil {
		errs = append(errs, "services: "+err.Error())
	} else {
		all = append(all, opps...)
	}
	if opps, err := ScanProcesses(opts...); err != nil {
		errs = append(errs, "processes: "+err.Error())
	} else {
		all = append(all, opps...)
	}
	if opps, err := ScanScheduledTasks(opts...); err != nil {
		errs = append(errs, "tasks: "+err.Error())
	} else {
		all = append(all, opps...)
	}
	if opps, err := ScanAutoElevate(opts...); err != nil {
		errs = append(errs, "autoelevate: "+err.Error())
	} else {
		all = append(all, opps...)
	}
	if len(errs) > 0 {
		return all, fmt.Errorf("dllhijack/ScanAll: partial failures: %s", strings.Join(errs, "; "))
	}
	return all, nil
}
