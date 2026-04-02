package evasion

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
