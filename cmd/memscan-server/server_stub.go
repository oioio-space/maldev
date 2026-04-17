//go:build !windows

package main

import "errors"

func run(addr string) error {
	return errors.New("memscan-server runs on Windows only")
}
