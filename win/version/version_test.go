//go:build windows

package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrent(t *testing.T) {
	v := Current()
	require.NotNil(t, v)
	assert.GreaterOrEqual(t, v.MajorVersion, uint32(10), "expected major version >= 10")
	assert.Greater(t, v.BuildNumber, uint32(0), "expected build number > 0")
}

func TestWindows(t *testing.T) {
	wv, err := Windows()
	require.NoError(t, err)
	require.NotNil(t, wv)
	assert.GreaterOrEqual(t, wv.Major, uint32(10), "expected major >= 10")
	assert.Greater(t, wv.Build, uint32(0), "expected build > 0")
	assert.NotEmpty(t, wv, "expected non-empty WindowsVersion")
}

func TestCVE202430088(t *testing.T) {
	info, err := CVE202430088()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Greater(t, info.Build, uint32(0))
	t.Logf("CVE-2024-30088 vulnerable=%v build=%d", info.Vulnerable, info.Build)
}

func TestVersionString(t *testing.T) {
	v := Current()
	require.NotNil(t, v)
	s := v.String()
	assert.NotEmpty(t, s, "expected non-empty version string")
	assert.NotEqual(t, "unknown", s, "expected a known version string")
}

// TestVersion_IsAtLeast covers IsAtLeast semantics across major /
// minor / build comparisons. Also exercises the equal-version path
// (must return true since "at least" is inclusive).
func TestVersion_IsAtLeast(t *testing.T) {
	cases := []struct {
		name string
		a, b *Version
		want bool
	}{
		{"Win11_24H2 >= Win10_22H2", WINDOWS_11_24H2, WINDOWS_10_22H2, true},
		{"Win10_22H2 >= Win11_24H2", WINDOWS_10_22H2, WINDOWS_11_24H2, false},
		{"Win11_24H2 >= Win11_24H2 (equal)", WINDOWS_11_24H2, WINDOWS_11_24H2, true},
		{"Win11_22H2 >= Win11_21H2 (build only)", WINDOWS_11_22H2, WINDOWS_11_21H2, true},
		{"Win11_21H2 >= Win11_22H2", WINDOWS_11_21H2, WINDOWS_11_22H2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.a.IsAtLeast(tc.b)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestAtLeast smoke-tests the package-level helper against the
// running host's actual version. Asserts a thresholded "Windows 10
// or later" check (the host must be ≥ Win10 to run our test suite).
func TestAtLeast(t *testing.T) {
	assert.True(t, AtLeast(WINDOWS_10_1507),
		"running Windows must be >= Win10 1507")
}
