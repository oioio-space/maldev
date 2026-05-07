package transform_test

import (
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

func TestAlignUpU32(t *testing.T) {
	cases := []struct {
		v, align, want uint32
	}{
		{0, 0x1000, 0},
		{1, 0x1000, 0x1000},
		{0x1000, 0x1000, 0x1000},
		{0x1001, 0x1000, 0x2000},
		{0xFFF, 0x200, 0x1000},
		{0x123, 0, 0x123}, // align == 0 returns v unchanged
	}
	for _, c := range cases {
		if got := transform.AlignUpU32(c.v, c.align); got != c.want {
			t.Errorf("AlignUpU32(%#x, %#x) = %#x, want %#x", c.v, c.align, got, c.want)
		}
	}
}

func TestAlignUpU64(t *testing.T) {
	cases := []struct {
		v, align, want uint64
	}{
		{0, 0x1000, 0},
		{1, 0x1000, 0x1000},
		{0x1000, 0x1000, 0x1000},
		{0x1001, 0x1000, 0x2000},
		{0x123456789, 0x10000, 0x123460000},
		{0x123, 0, 0x123}, // align == 0 returns v unchanged
	}
	for _, c := range cases {
		if got := transform.AlignUpU64(c.v, c.align); got != c.want {
			t.Errorf("AlignUpU64(%#x, %#x) = %#x, want %#x", c.v, c.align, got, c.want)
		}
	}
}
