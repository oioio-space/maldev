//go:build !linux && !windows

package main

import "fmt"

// executePayload is a stub on platforms that don't have a working
// in-process / temp-file dispatcher in this command. Operators on
// darwin / *bsd / etc. should use [packer.MatchBundleHost] +
// [packer.UnpackBundle] from a custom launcher tailored to their
// target's exec model.
func executePayload(payload []byte, args []string) error {
	return fmt.Errorf("bundle-launcher: payload exec not supported on this OS")
}
