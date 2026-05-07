package poly

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// Engine drives N-round SGN-style polymorphic encoding.
//
// EncodePayload applies N rounds of byte-level XOR with per-round
// random keys and returns both the encoded bytes and the Round
// descriptors. The stage1 emitter consumes the Round descriptors to
// build the matching decoders; at runtime the decoders apply in
// REVERSE order (round N first, round 1 last) to peel each layer.
type Engine struct {
	rng    *mrand.Rand
	rounds int
}

// NewEngine seeds the engine with a deterministic seed (for
// reproducible tests) or, when seed == 0, with a fresh seed drawn
// from crypto/rand (for production unpredictability).
//
// rounds must be in [1, 10]. Values outside that range are rejected
// because the stage-1 stub size scales linearly with rounds, and
// beyond 10 the size overhead outweighs the polymorphism benefit.
func NewEngine(seed int64, rounds int) (*Engine, error) {
	if rounds < 1 || rounds > 10 {
		return nil, fmt.Errorf("poly: rounds %d out of range [1,10]", rounds)
	}
	if seed == 0 {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, fmt.Errorf("poly: crypto/rand seed: %w", err)
		}
		seed = int64(binary.LittleEndian.Uint64(buf[:]))
	}
	return &Engine{rng: mrand.New(mrand.NewSource(seed)), rounds: rounds}, nil
}

// Round captures the per-round parameters the stage1 emitter needs to
// build a single decoder loop.
type Round struct {
	Key   uint8 // single-byte key applied uniformly to every payload byte
	Subst Subst // chosen encode/decode pair (canonicalXOR / subNegate / addComplement)
	// Register assignments — freshly allocated each round from the pool so
	// consecutive decoder loops use different registers, maximising the
	// byte-level difference across the emitted machine code.
	KeyReg, ByteReg, SrcReg, CntReg amd64.Reg
}

// EncodePayload copies data, applies N rounds of XOR encoding in
// order (round 0 first, round N-1 last), and returns:
//   - encoded: the encoded payload bytes
//   - rounds: one Round per encoding round, in application order
//   - err: non-nil only if the register pool is exhausted (impossible
//     with N ≤ 10 since only 4 of the 14 GPRs are needed per round and
//     they are released before the next round begins)
//
// The stage1 emitter must emit decoders in REVERSE order: rounds[N-1]
// first (outermost layer), rounds[0] last (innermost layer).
func (e *Engine) EncodePayload(data []byte) (encoded []byte, rounds []Round, err error) {
	return e.EncodePayloadExcluding(data)
}

// EncodePayloadExcluding is [EncodePayload] with caller-supplied
// register exclusions. Stage 1 reserves the CALL+POP+ADD baseReg
// (typically R15) so per-round register randomisation cannot
// clobber the runtime TextRVA pointer it carries across all
// rounds. EncodePayload calls this with no exclusions.
func (e *Engine) EncodePayloadExcluding(data []byte, excluded ...amd64.Reg) (encoded []byte, rounds []Round, err error) {
	encoded = append([]byte(nil), data...) // defensive copy; caller's slice is never modified
	rounds = make([]Round, e.rounds)
	pool := NewRegPoolExcluding(e.rng, excluded...)

	for i := 0; i < e.rounds; i++ {
		// Four registers, one role each: key constant, current byte,
		// source pointer, loop counter. Released before the next round
		// so the pool stays at 14 throughout.
		keyReg, kerr := pool.Take()
		byteReg, berr := pool.Take()
		srcReg, serr := pool.Take()
		cntReg, cerr := pool.Take()
		if kerr != nil || berr != nil || serr != nil || cerr != nil {
			// Should never happen: we release 4 before taking 4 next round.
			return nil, nil, fmt.Errorf("poly: register pool exhausted at round %d", i)
		}

		key := uint8(e.rng.Intn(256))
		subst := PickSubst(e.rng)

		rounds[i] = Round{
			Key:     key,
			Subst:   subst,
			KeyReg:  keyReg,
			ByteReg: byteReg,
			SrcReg:  srcReg,
			CntReg:  cntReg,
		}

		for j := range encoded {
			encoded[j] = subst.Encode(encoded[j], key)
		}

		pool.Release(keyReg)
		pool.Release(byteReg)
		pool.Release(srcReg)
		pool.Release(cntReg)
	}

	return encoded, rounds, nil
}

// Rounds returns the configured round count.
func (e *Engine) Rounds() int { return e.rounds }
