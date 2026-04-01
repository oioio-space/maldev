//go:build windows

package injection

func newPlatformInjector(cfg *Config) (Injector, error) {
	return newWindowsInjector(cfg)
}
