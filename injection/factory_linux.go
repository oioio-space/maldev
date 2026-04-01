//go:build linux

package injection

func newPlatformInjector(cfg *Config) (Injector, error) {
	return newLinuxInjector(cfg)
}
