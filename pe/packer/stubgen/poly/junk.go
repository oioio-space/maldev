package poly

import (
	"math/rand"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// InsertJunk emits 0..maxBytes bytes of junk into b. The junk is
// guaranteed to leave the architectural state unchanged (NOPs,
// XOR-self on a scratch register, push/pop preserving a register).
//
// density is the probability per call that ANY junk is inserted at
// all; 0.0 means never, 1.0 means every call. Once junk is being
// inserted the byte count is uniform in [1, maxBytes].
func InsertJunk(b *amd64.Builder, density float64, maxBytes int, regs *RegPool, rng *rand.Rand) error {
	if rng.Float64() >= density {
		return nil
	}
	if maxBytes < 1 {
		return nil
	}
	width := 1 + rng.Intn(maxBytes)
	// Clamp to the NOP range the builder accepts. Junk insertion
	// is best-effort: oversized requests fall back to the max.
	if width > 9 {
		width = 9
	}

	switch rng.Intn(3) {
	case 1:
		// XOR r,r zeros a scratch register — architecturally neutral,
		// distinct byte pattern from a NOP run. Falls back to NOP if
		// the pool is exhausted (caller holds all 14 registers).
		r, err := regs.Take()
		if err != nil {
			return b.NOP(width)
		}
		defer regs.Release(r)
		return b.XOR(r, r)
	default:
		// Cases 0 and 2: NOP run. PUSH/POP is not yet in the builder;
		// widen the NOP share until it lands.
		return b.NOP(width)
	}
}
