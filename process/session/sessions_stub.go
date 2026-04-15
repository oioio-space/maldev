//go:build !windows

package session

import "errors"

// SessionState is a stub on non-Windows platforms.
type SessionState uint32

// Info is a stub on non-Windows platforms.
type Info struct {
	ID     uint32
	Name   string
	State  SessionState
	User   string
	Domain string
}

// List returns an error on non-Windows platforms.
func List() ([]Info, error) { return nil, errors.New("session: Windows only") }

// Active returns an error on non-Windows platforms.
func Active() ([]Info, error) { return nil, errors.New("session: Windows only") }

// String is a stub on non-Windows platforms.
func (s SessionState) String() string { return "Unsupported" }
