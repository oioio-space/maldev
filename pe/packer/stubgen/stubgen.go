package stubgen

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// Options drives Generate.
type Options struct {
	// Input is the PE/ELF binary to transform in place.
	Input []byte
	// Rounds is the number of SGN encoding rounds, 1..10; default 3.
	Rounds int
	// Seed drives the poly engine. Zero = crypto-random.
	Seed int64
	// StubMaxSize is the pre-reserved byte count for the appended stub
	// section. Zero defaults to 4096.
	StubMaxSize uint32
	// CipherKey, when non-nil, is used as the XOR key for .text
	// encryption. When nil a fresh 32-byte key is generated.
	CipherKey []byte
}

// Sentinels surfaced by Generate.
var (
	// ErrInvalidRounds fires when Options.Rounds is outside [1, 10].
	ErrInvalidRounds = errors.New("stubgen: rounds out of range")
	// ErrNoInput fires when Options.Input is nil or empty.
	ErrNoInput = errors.New("stubgen: no input bytes")
)

// Generate runs the UPX-style transform pipeline:
//
//  1. Detect format (PE vs ELF)
//  2. PlanPE / PlanELF (compute RVAs)
//  3. XOR-encrypt input's .text with CipherKey (or a fresh random key)
//  4. poly.Engine.EncodePayload (SGN N-round)
//  5. stage1.EmitStub (CALL+POP+ADD prologue + N rounds + JMP-OEP)
//  6. stage1.PatchTextDisplacement (post-Encode prologue fixup)
//  7. transform.InjectStubPE / InjectStubELF (write modified binary)
//
// Returns the modified binary and the key used to encrypt .text.
func Generate(opts Options) ([]byte, []byte, error) {
	if len(opts.Input) == 0 {
		return nil, nil, ErrNoInput
	}
	rounds := opts.Rounds
	if rounds == 0 {
		rounds = 3
	}
	if rounds < 1 || rounds > 10 {
		return nil, nil, fmt.Errorf("%w: rounds=%d", ErrInvalidRounds, rounds)
	}
	stubMaxSize := opts.StubMaxSize
	if stubMaxSize == 0 {
		stubMaxSize = 4096
	}
	seed := opts.Seed
	if seed == 0 {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, nil, fmt.Errorf("stubgen: seed: %w", err)
		}
		seed = int64(binary.LittleEndian.Uint64(buf[:]))
	}

	// 1. Detect format + Plan
	format := transform.DetectFormat(opts.Input)
	var plan transform.Plan
	switch format {
	case transform.FormatPE:
		var err error
		plan, err = transform.PlanPE(opts.Input, stubMaxSize)
		if err != nil {
			return nil, nil, fmt.Errorf("stubgen: PlanPE: %w", err)
		}
	case transform.FormatELF:
		var err error
		plan, err = transform.PlanELF(opts.Input, stubMaxSize)
		if err != nil {
			return nil, nil, fmt.Errorf("stubgen: PlanELF: %w", err)
		}
	default:
		return nil, nil, transform.ErrUnsupportedInputFormat
	}

	// 2. Extract .text bytes
	textBytes := opts.Input[plan.TextFileOff : plan.TextFileOff+plan.TextSize]

	// 3. Encrypt .text with XOR key.
	// SGN's polymorphic engine already provides AV-evasion cover; the
	// XOR layer ensures .text bytes in the output are not plaintext.
	// Phase 1c+ pipeline integration (AES-GCM) replaces this in a
	// future chantier.
	key := opts.CipherKey
	if key == nil {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, nil, fmt.Errorf("stubgen: cipher key: %w", err)
		}
	}
	encrypted := make([]byte, len(textBytes))
	for i := range textBytes {
		encrypted[i] = textBytes[i] ^ key[i%len(key)]
	}

	// 4. SGN-encode the encrypted bytes
	eng, err := poly.NewEngine(seed, rounds)
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: NewEngine: %w", err)
	}
	finalEncoded, polyRounds, err := eng.EncodePayload(encrypted)
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: EncodePayload: %w", err)
	}

	// 5. Emit stub asm
	b, err := amd64.New()
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: amd64.New: %w", err)
	}
	if err := stage1.EmitStub(b, plan, polyRounds); err != nil {
		return nil, nil, fmt.Errorf("stubgen: EmitStub: %w", err)
	}
	stubBytes, err := b.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: amd64.Encode: %w", err)
	}
	if uint32(len(stubBytes)) > plan.StubMaxSize {
		return nil, nil, fmt.Errorf("%w: %d > %d", transform.ErrStubTooLarge, len(stubBytes), plan.StubMaxSize)
	}

	// 6. Patch CALL+POP+ADD prologue: replace sentinel with real displacement
	if _, err := stage1.PatchTextDisplacement(stubBytes, plan); err != nil {
		return nil, nil, fmt.Errorf("stubgen: PatchTextDisplacement: %w", err)
	}

	// 7. Inject into input
	var out []byte
	switch format {
	case transform.FormatPE:
		out, err = transform.InjectStubPE(opts.Input, finalEncoded, stubBytes, plan)
	case transform.FormatELF:
		out, err = transform.InjectStubELF(opts.Input, finalEncoded, stubBytes, plan)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: Inject: %w", err)
	}

	return out, key, nil
}
