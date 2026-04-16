//go:build !windows

package hook

// ProbeResult holds captured arguments from a probed function call.
// On non-Windows platforms all methods are no-ops.
type ProbeResult struct {
	Args [18]uintptr
	Ret  uintptr
}

// NonZeroArgs returns nil on non-Windows platforms.
func (r ProbeResult) NonZeroArgs() []int { return nil }

// NonZeroCount returns 0 on non-Windows platforms.
func (r ProbeResult) NonZeroCount() int { return 0 }

// InstallProbe is unsupported on non-Windows platforms.
func InstallProbe(_ uintptr, _ func(ProbeResult), _ ...HookOption) (*Hook, error) {
	return nil, errUnsupported
}

// InstallProbeByName is unsupported on non-Windows platforms.
func InstallProbeByName(_, _ string, _ func(ProbeResult), _ ...HookOption) (*Hook, error) {
	return nil, errUnsupported
}
