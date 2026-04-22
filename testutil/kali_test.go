package testutil

import (
	"testing"
)

// TestKaliEnvResolvers exercises every kali* env-var resolver with both the
// override path (env var set) and the default path (env var unset). Separate
// subtests guarantee a clean environment between cases via t.Setenv.
func TestKaliEnvResolvers(t *testing.T) {
	cases := []struct {
		name    string
		envKey  string
		resolve func() string
		custom  string
		fallback string
	}{
		{"kaliSSHHost", "MALDEV_KALI_SSH_HOST", kaliSSHHost, "10.0.0.5", "localhost"},
		{"kaliSSHPort", "MALDEV_KALI_SSH_PORT", kaliSSHPort, "2999", KaliSSHPort},
		{"kaliSSHKey", "MALDEV_KALI_SSH_KEY", kaliSSHKey, "/etc/keys/custom", KaliSSHKey},
		{"kaliUser", "MALDEV_KALI_USER", kaliUser, "redteam", KaliUser},
	}
	for _, c := range cases {
		t.Run(c.name+"/override", func(t *testing.T) {
			t.Setenv(c.envKey, c.custom)
			if got := c.resolve(); got != c.custom {
				t.Errorf("%s with %s=%q = %q, want %q", c.name, c.envKey, c.custom, got, c.custom)
			}
		})
		t.Run(c.name+"/default", func(t *testing.T) {
			t.Setenv(c.envKey, "") // explicit unset-to-empty; treated as "not set"
			if got := c.resolve(); got != c.fallback {
				t.Errorf("%s default = %q, want %q", c.name, got, c.fallback)
			}
		})
	}
}
