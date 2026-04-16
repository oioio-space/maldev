//go:build windows

package hook

import "sync"

// Target describes a single function to hook by DLL and export name.
type Target struct {
	DLL     string
	Func    string
	Handler interface{}
}

// HookGroup manages a set of hooks installed together, with atomic rollback on
// partial failure so callers never end up with a half-installed state.
type HookGroup struct {
	hooks []*Hook
	mu    sync.Mutex
}

// InstallAll installs hooks for every Target in order. If any hook fails, all
// previously installed hooks are removed before returning the error.
func InstallAll(targets []Target, opts ...HookOption) (*HookGroup, error) {
	g := &HookGroup{}
	for _, t := range targets {
		h, err := InstallByName(t.DLL, t.Func, t.Handler, opts...)
		if err != nil {
			g.RemoveAll()
			return nil, err
		}
		g.hooks = append(g.hooks, h)
	}
	return g, nil
}

// RemoveAll uninstalls every hook in the group. It continues past individual
// errors and returns the first error encountered.
func (g *HookGroup) RemoveAll() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	var firstErr error
	for _, h := range g.hooks {
		if err := h.Remove(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	g.hooks = nil
	return firstErr
}

// Hooks returns the installed hooks in installation order.
func (g *HookGroup) Hooks() []*Hook { return g.hooks }
