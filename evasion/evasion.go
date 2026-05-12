package evasion

import (
	"fmt"
	"sort"
	"strings"
)

// Technique is a single evasion action that can be applied.
// Each evasion sub-package (amsi, etw, unhook, acg, blockdlls)
// exports constructors that return Technique values.
//
// The caller parameter controls how Windows memory protection changes
// are made. Pass nil for standard WinAPI (VirtualProtect), or a
// configured *wsyscall.Caller for direct/indirect syscalls.
// On non-Windows platforms, caller should be nil.
//
// Example:
//
//	techniques := []evasion.Technique{
//	    amsi.ScanBufferPatch(),
//	    etw.All(),
//	    unhook.Classic("NtAllocateVirtualMemory"),
//	}
//	errs := evasion.ApplyAll(techniques, nil)
type Technique interface {
	// Name returns a human-readable identifier (e.g., "amsi:ScanBuffer").
	Name() string

	// Apply executes the evasion technique.
	// caller may be nil (falls back to standard WinAPI).
	Apply(caller Caller) error
}

// Caller is an opaque type for syscall method configuration.
// On Windows, pass a *wsyscall.Caller. On other platforms, pass nil.
// Using interface{} avoids importing win/syscall in this cross-platform package.
type Caller = interface{}

// ApplyAll executes every technique in order.
// Returns a map of technique name to error for any that failed.
// Returns nil if all succeeded.
//
// Example:
//
//	errs := evasion.ApplyAll(techniques, nil)
//	if errs != nil {
//	    for name, err := range errs {
//	        log.Printf("evasion %s failed: %v", name, err)
//	    }
//	}
func ApplyAll(techniques []Technique, caller Caller) map[string]error {
	errs := make(map[string]error)
	for _, t := range techniques {
		if err := t.Apply(caller); err != nil {
			errs[t.Name()] = err
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// ApplyAllAggregated runs every technique like [ApplyAll] but folds
// the per-technique failures into a single error whose message lists
// each failing technique alphabetically. Returns nil if every
// technique succeeded. Use this when the caller only needs to know
// "did anything fail" and wants a single value to log or return.
//
// Example:
//
//	if err := evasion.ApplyAllAggregated(techniques, nil); err != nil {
//	    log.Printf("evasion: %v", err)
//	}
func ApplyAllAggregated(techniques []Technique, caller Caller) error {
	errs := ApplyAll(techniques, caller)
	if errs == nil {
		return nil
	}
	names := make([]string, 0, len(errs))
	for name := range errs {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s: %v", name, errs[name]))
	}
	return fmt.Errorf("evasion: %d/%d techniques failed: %s",
		len(errs), len(techniques), strings.Join(parts, "; "))
}
