//go:build !windows

package stealthopen

import "os"

// Stealth is the non-Windows placeholder. It exists so cross-platform
// code can declare Opener fields of type *stealthopen.Stealth without
// build-tag gymnastics, but any call on this platform fails — NTFS
// Object IDs are a Windows-only filesystem feature.
type Stealth struct {
	VolumePath string
	ObjectID   [16]byte
}

// Open always returns errUnsupported on non-Windows.
func (s *Stealth) Open(_ string) (*os.File, error) { return nil, errUnsupported }

// NewStealth always returns errUnsupported on non-Windows.
func NewStealth(_ string) (*Stealth, error) { return nil, errUnsupported }

// VolumeFromPath always returns errUnsupported on non-Windows.
func VolumeFromPath(_ string) (string, error) { return "", errUnsupported }
