//go:build !windows

package main

import "errors"

func runSelf(cfg demoConfig) error {
	return errors.New("self scenario: Windows only")
}
