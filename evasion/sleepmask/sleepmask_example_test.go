//go:build windows

package sleepmask_test

import (
	"context"
	"time"

	"github.com/oioio-space/maldev/evasion/sleepmask"
)

// New returns a Mask over the given regions with default cipher + strategy
// (XOR + InlineStrategy). Sleep encrypts, waits, decrypts.
func ExampleNew() {
	mask := sleepmask.New(sleepmask.Region{Addr: 0xDEADBEEF, Size: 4096})
	_ = mask.Sleep(context.Background(), 30*time.Second)
}

// WithCipher / WithStrategy let you swap the defaults. Use AESCTRCipher
// when AESNI is available; EkkoStrategy for ROP-based masking.
func ExampleMask_WithCipher() {
	mask := sleepmask.
		New(sleepmask.Region{Addr: 0xDEADBEEF, Size: 4096}).
		WithCipher(&sleepmask.AESCTRCipher{}).
		WithStrategy(&sleepmask.EkkoStrategy{})
	_ = mask.Sleep(context.Background(), 60*time.Second)
}
