//go:build !windows

package cet

import "errors"

// Marker is the ENDBR64 opcode prefix; same on non-Windows for portable use.
var Marker = []byte{0xF3, 0x0F, 0x1E, 0xFA}

// Enforced always returns false on non-Windows platforms.
func Enforced() bool { return false }

// Disable returns an error on non-Windows platforms.
func Disable() error { return errors.New("cet: Windows only") }

// Wrap prepends Marker to sc unless sc already begins with it.
func Wrap(sc []byte) []byte {
	if len(sc) >= 4 && sc[0] == 0xF3 && sc[1] == 0x0F && sc[2] == 0x1E && sc[3] == 0xFA {
		return sc
	}
	out := make([]byte, 0, len(sc)+4)
	out = append(out, Marker...)
	out = append(out, sc...)
	return out
}
