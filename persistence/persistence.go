package persistence

// Mechanism is a persistence technique that can be installed and removed.
// Each persistence sub-package (registry, startup, scheduler, service)
// exports constructors that return Mechanism values, enabling composable
// redundant persistence.
//
// Example:
//
//	mechanisms := []persistence.Mechanism{
//	    registry.RunKey(registry.HiveCurrentUser, "MyApp", `C:\payload.exe`),
//	    startup.Shortcut("MyApp", `C:\payload.exe`, ""),
//	}
//	errs := persistence.InstallAll(mechanisms)
type Mechanism interface {
	// Name returns a human-readable identifier (e.g., "registry:HKCU:Run").
	Name() string

	// Install activates the persistence mechanism.
	Install() error

	// Uninstall removes the persistence mechanism.
	Uninstall() error

	// Installed reports whether the mechanism is currently active.
	Installed() (bool, error)
}

// InstallAll activates every mechanism in order.
// Returns a map of mechanism name to error for any that failed.
// Returns nil if all succeeded.
func InstallAll(mechanisms []Mechanism) map[string]error {
	errs := make(map[string]error)
	for _, m := range mechanisms {
		if err := m.Install(); err != nil {
			errs[m.Name()] = err
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// UninstallAll removes every mechanism in order.
// Returns a map of mechanism name to error for any that failed.
// Returns nil if all succeeded.
func UninstallAll(mechanisms []Mechanism) map[string]error {
	errs := make(map[string]error)
	for _, m := range mechanisms {
		if err := m.Uninstall(); err != nil {
			errs[m.Name()] = err
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}
