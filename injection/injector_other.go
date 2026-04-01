//go:build !windows && !linux

package injection

import "fmt"

func newPlatformInjector(cfg *Config) (Injector, error) {
	return nil, fmt.Errorf("injection not supported on this platform")
}
