package dllhijack

import "testing"

// TestIsApiSet locks the ApiSet-contract matcher so future refactors
// don't regress the hijack-candidate filter. Inputs reflect names
// surfaced by real PE import tables on Win10/11 + a few negatives
// that look superficially close.
func TestIsApiSet(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"api-ms-win-core-libraryloader-l1-2-0.dll", true},
		{"api-ms-win-crt-runtime-l1-1-0.dll", true},
		{"API-MS-WIN-CORE-PROCESSTHREADS-L1-1-2.DLL", true}, // case-insensitive
		{"ext-ms-win-ntuser-window-l1-1-0.dll", true},
		{"ext-ms-win-rtcore-ntuser-window-ext-l1-1-0.dll", true},

		// Negatives — real DLLs that should never match.
		{"kernel32.dll", false},
		{"version.dll", false},
		{"msvcrt.dll", false},
		{"ucrtbase.dll", false},
		{"my-app-api.dll", false},   // looks like apiset but isn't
		{"api-something.dll", false}, // missing -ms-win- segment
		{"ext-something.dll", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isApiSet(c.name); got != c.want {
			t.Errorf("isApiSet(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
