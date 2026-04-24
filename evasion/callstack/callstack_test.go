package callstack

import (
	"strings"
	"testing"
)

// TestFrameString includes every field so operators can spot which
// piece is wrong at a glance. Keep the format stable.
func TestFrameString(t *testing.T) {
	f := Frame{
		ReturnAddress: 0x7FFE1234,
		ImageBase:     0x7FFE0000,
		RuntimeFunction: RuntimeFunction{
			BeginAddress:      0x1000,
			EndAddress:        0x2000,
			UnwindInfoAddress: 0x3000,
		},
	}
	got := f.String()
	for _, want := range []string{"RIP=0x7FFE1234", "base=0x7FFE0000", "unwind=0x3000"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}

func TestValidate_GoodChain(t *testing.T) {
	chain := []Frame{
		{
			ReturnAddress: 0x7FFE1500,
			ImageBase:     0x7FFE0000,
			RuntimeFunction: RuntimeFunction{
				BeginAddress:      0x1000,
				EndAddress:        0x2000,
				UnwindInfoAddress: 0x5000,
			},
		},
	}
	if err := Validate(chain); err != nil {
		t.Fatalf("Validate good chain: %v", err)
	}
}

func TestValidate_RejectsBadFields(t *testing.T) {
	cases := []struct {
		name string
		f    Frame
		want string
	}{
		{"zero RIP", Frame{}, "zero ReturnAddress"},
		{"zero base",
			Frame{ReturnAddress: 0x1},
			"zero ImageBase"},
		{"zero unwind",
			Frame{ReturnAddress: 0x1, ImageBase: 0x1},
			"zero UnwindInfoAddress"},
		{"RIP out of bounds",
			Frame{
				ReturnAddress: 0x7FFE9999,
				ImageBase:     0x7FFE0000,
				RuntimeFunction: RuntimeFunction{
					BeginAddress:      0x1000,
					EndAddress:        0x2000,
					UnwindInfoAddress: 0x5000,
				},
			},
			"outside"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Validate([]Frame{c.f})
			if err == nil {
				t.Fatalf("Validate should have rejected %q", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}
