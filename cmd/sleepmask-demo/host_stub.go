//go:build !windows

package main

import "errors"

func runHost(cfg demoConfig) error {
	return errors.New("host scenario: Windows only")
}
