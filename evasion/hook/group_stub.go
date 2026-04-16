//go:build !windows

package hook

// Target describes a single function to hook by DLL and export name.
type Target struct {
	DLL     string
	Func    string
	Handler interface{}
}

// HookGroup manages a set of hooks installed together (unsupported on this platform).
type HookGroup struct{}

// InstallAll installs hooks for every Target (unsupported on this platform).
func InstallAll(_ []Target, _ ...HookOption) (*HookGroup, error) { return nil, errUnsupported }

// RemoveAll uninstalls every hook in the group.
func (g *HookGroup) RemoveAll() error { return nil }

// Hooks returns the installed hooks.
func (g *HookGroup) Hooks() []*Hook { return nil }
