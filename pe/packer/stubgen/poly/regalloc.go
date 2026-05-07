package poly

import (
	"fmt"
	"math/rand"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// RegPool hands out registers from a randomly-shuffled list of
// general-purpose registers. Take returns a fresh register and
// removes it from the pool; Release puts it back. Used by the
// SGN engine to assign roles (key, byte, src, count) to fresh
// registers each round.
type RegPool struct {
	available []amd64.Reg
	rng       *rand.Rand
}

// NewRegPool returns a pool seeded by the given math/rand source.
// The pool starts with all 14 GPRs (RSP and RBP excluded).
func NewRegPool(rng *rand.Rand) *RegPool {
	return NewRegPoolExcluding(rng)
}

// NewRegPoolExcluding is like NewRegPool but additionally removes
// the given registers from the pool. Stage 1 callers reserve the
// CALL+POP+ADD baseReg (typically R15) so per-round register
// randomisation cannot clobber the runtime TextRVA pointer it
// holds across all rounds.
func NewRegPoolExcluding(rng *rand.Rand, excluded ...amd64.Reg) *RegPool {
	all := amd64.AllGPRs()
	if len(excluded) > 0 {
		filtered := all[:0]
		for _, r := range all {
			drop := false
			for _, e := range excluded {
				if r == e {
					drop = true
					break
				}
			}
			if !drop {
				filtered = append(filtered, r)
			}
		}
		all = filtered
	}
	rng.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	return &RegPool{available: all, rng: rng}
}

// Take pops the next register from the shuffled pool. Returns an
// error when the pool is exhausted (which means the caller asked
// for more than 14 registers — an algorithmic bug).
func (p *RegPool) Take() (amd64.Reg, error) {
	if len(p.available) == 0 {
		return 0, fmt.Errorf("poly: register pool exhausted")
	}
	r := p.available[len(p.available)-1]
	p.available = p.available[:len(p.available)-1]
	return r, nil
}

// Release returns a register to the pool. Inserted at a random
// position so later Take calls don't always reuse the most-
// recently-released register (which would form a recognizable
// pattern across packs).
func (p *RegPool) Release(r amd64.Reg) {
	idx := p.rng.Intn(len(p.available) + 1)
	p.available = append(p.available, r)
	// Swap the appended element into the random position.
	p.available[idx], p.available[len(p.available)-1] = p.available[len(p.available)-1], p.available[idx]
}

// Available reports how many registers remain in the pool.
func (p *RegPool) Available() int { return len(p.available) }
