//go:build !linux && !windows

package antivm

// hasPortIOPrivileges always returns false on non-Linux non-Windows
// targets (darwin, freebsd, …): the [BackdoorVMware] probe needs a
// platform-specific privilege escalation (iopl on Linux, kernel driver
// on Windows) that we don't model here. Returning false short-circuits
// the wrapper before the asm runs.
func hasPortIOPrivileges() bool { return false }

// dropPortIOPrivileges is a no-op on these targets — privilege was
// never raised. Symmetric API the wrapper expects.
func dropPortIOPrivileges() {}
