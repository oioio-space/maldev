//go:build !windows

package main

import "errors"

func run(_, _, _, _, _, _ string) error {
	return errors.New("memscan-harness runs on Windows only")
}
