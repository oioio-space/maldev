package lsasparse

import "testing"

// TestDefaultTemplates_RegisteredAtInit asserts that the canonical
// Win10/Win11 templates are reachable via templateFor() without any
// operator setup. This is the "no RegisterTemplate boilerplate"
// guarantee — a v0.23.x dump from one of the documented builds parses
// out of the box.
//
// Test calls registerDefaultTemplates() explicitly so it survives
// being run after a sibling test that called resetTemplates().
func TestDefaultTemplates_RegisteredAtInit(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()
	registerDefaultTemplates()

	cases := []struct {
		name  string
		build uint32
		want  bool
	}{
		{"Win10 19H1 (1903)", 18362, true},
		{"Win10 22H2", 19045, true},
		{"Win11 21H2", 22000, true},
		{"Win11 22H2 pre-22622", 22621, true},

		// Out-of-range builds: no template, ErrUnsupportedBuild.
		{"Win10 RTM (1507)", 10240, false},
		{"Win10 1607", 14393, false},
		{"Win10 1809", 17763, false},  // earlier than 19H1 — not yet covered
		{"Win11 22622", 22622, false}, // newer MSV signature — needs distinct template
		{"Server 2025 / Win11 24H2", 26100, false},
		{"future", 99999, false},
	}

	for _, tc := range cases {
		got := templateFor(tc.build) != nil
		if got != tc.want {
			t.Errorf("templateFor(%d %s) coverage = %v, want %v",
				tc.build, tc.name, got, tc.want)
		}
	}
}

// TestDefaultTemplates_PassValidation confirms every shipping
// Template satisfies the same validate() guard that RegisterTemplate
// runs at registration. Catches drift if a future edit forgets a
// required pattern field.
func TestDefaultTemplates_PassValidation(t *testing.T) {
	for i, tpl := range builtinTemplates {
		if err := tpl.validate(); err != nil {
			t.Errorf("builtinTemplates[%d] (build %d-%d): validate: %v",
				i, tpl.BuildMin, tpl.BuildMax, err)
		}
	}
}

// TestDefaultTemplates_LayoutsConsistent asserts every shipping
// template's MSVLayout has NodeSize >= every offset we read. Bug
// guard against a future edit that adds an offset without growing
// NodeSize, which would silently truncate the bytes the walker
// projects through the layout.
func TestDefaultTemplates_LayoutsConsistent(t *testing.T) {
	for i, tpl := range builtinTemplates {
		l := tpl.MSVLayout
		maxOff := l.LUIDOffset
		for _, o := range []uint32{
			l.UserNameOffset, l.LogonDomainOffset, l.LogonServerOffset,
			l.LogonTypeOffset, l.LogonTimeOffset, l.SIDOffset,
			l.CredentialsOffset,
		} {
			if o > maxOff {
				maxOff = o
			}
		}
		// CredentialsOffset is a pointer (8 bytes); UNICODE_STRINGs are
		// 16 bytes; LUID is 8 bytes. Demand at least 16 bytes of slack
		// past the largest offset so every read fits.
		need := maxOff + 16
		if l.NodeSize < need {
			t.Errorf("builtinTemplates[%d] (build %d-%d): NodeSize 0x%X < required 0x%X",
				i, tpl.BuildMin, tpl.BuildMax, l.NodeSize, need)
		}
	}
}

// TestDefaultTemplates_NoBuildOverlap asserts no two shipping
// templates cover the same BuildNumber. Overlap would make
// templateFor's "first match wins" rule depend on registration order
// — a footgun for future edits.
func TestDefaultTemplates_NoBuildOverlap(t *testing.T) {
	for i := 0; i < len(builtinTemplates); i++ {
		for j := i + 1; j < len(builtinTemplates); j++ {
			a, b := builtinTemplates[i], builtinTemplates[j]
			if a.BuildMin <= b.BuildMax && b.BuildMin <= a.BuildMax {
				t.Errorf("builtinTemplates[%d] (%d-%d) overlaps [%d] (%d-%d)",
					i, a.BuildMin, a.BuildMax, j, b.BuildMin, b.BuildMax)
			}
		}
	}
}
