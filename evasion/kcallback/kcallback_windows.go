//go:build windows && amd64

package kcallback

import "errors"

// errNotImplemented is a scaffold sentinel filled by C3.3.
var errNotImplemented = errors.New("kcallback: not implemented yet")

// Enumerate reads the three callback arrays described by tab via
// reader, resolves each callback's owning driver, and returns the
// concatenated slice. Entries whose low bit is zero (disabled) are
// included but have Enabled=false.
//
// Requires the caller to have populated tab.*RoutineRVA for the
// current ntoskrnl build. See docs/techniques/evasion/kernel-
// callback-removal.md for the PDB-derivation workflow.
func Enumerate(reader KernelReader, tab OffsetTable) ([]Callback, error) {
	_ = reader
	_ = tab
	return nil, errNotImplemented
}
