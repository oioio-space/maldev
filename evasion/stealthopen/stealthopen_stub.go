//go:build !windows

package stealthopen

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("stealthopen: not supported on this platform")

func GetObjectID(_ string) ([16]byte, error)         { return [16]byte{}, errUnsupported }
func SetObjectID(_ string, _ [16]byte) error          { return errUnsupported }
func OpenByID(_ string, _ [16]byte) (*os.File, error) { return nil, errUnsupported }
