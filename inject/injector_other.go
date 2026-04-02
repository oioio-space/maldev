//go:build !windows && !linux

package inject

import "fmt"

func newPlatformInjector(cfg *Config) (Injector, error) {
	return nil, fmt.Errorf("injection not supported on this platform")
}
