package packer

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/crypto"
)

// PipelineOp identifies the kind of transformation a [PipelineStep]
// performs. Pack runs steps in slice order; Unpack runs them in
// reverse.
type PipelineOp uint8

const (
	OpCipher  PipelineOp = 1 // AEAD or stream cipher (key-driven)
	OpPermute PipelineOp = 2 // byte permutation (S-Box, Matrix, ArithShift, XOR)
)

// String returns the canonical lowercase op name.
func (o PipelineOp) String() string {
	switch o {
	case OpCipher:
		return "cipher"
	case OpPermute:
		return "permute"
	case OpCompress:
		return "compress"
	default:
		return fmt.Sprintf("op(%d)", uint8(o))
	}
}

// Permutation enumerates the byte-permutation algorithms a
// `OpPermute` step can pick.
type Permutation uint8

const (
	PermutationXOR        Permutation = 0 // XOR with repeating key
	PermutationArithShift Permutation = 1 // crypto.ArithShift (additive shift mod 256)
	PermutationSBox       Permutation = 2 // crypto.SubstituteBytes (key = 256+256-byte sbox+inverse pair)
)

// String returns the canonical lowercase permutation name.
func (p Permutation) String() string {
	switch p {
	case PermutationXOR:
		return "xor"
	case PermutationArithShift:
		return "arith-shift"
	case PermutationSBox:
		return "sbox"
	default:
		return fmt.Sprintf("permutation(%d)", uint8(p))
	}
}

// PipelineStep describes one transformation in the pipeline.
// Algo's meaning is Op-dependent: for OpCipher it's a [Cipher];
// for OpPermute it's a [Permutation]. The Key bytes are the
// material the step needs to reverse — when nil at Pack time,
// the packer generates one and writes it into the returned
// [PipelineKeys].
type PipelineStep struct {
	Op   PipelineOp
	Algo uint8
	Key  []byte
}

// PipelineKeys is the per-step key material returned by
// [PackPipeline]. Index i carries the key produced (or
// echoed) for `Pipeline[i]`. Operators must transport both
// the blob AND the keys to the unpacker; the wire format
// only carries the Op + Algo of each step, never the key.
type PipelineKeys [][]byte

// Sentinels for the pipeline layer.
var (
	// ErrEmptyPipeline fires when [PackPipeline] is called with
	// an empty pipeline. Use the single-step [Pack] for the
	// AES-GCM-only convenience case.
	ErrEmptyPipeline = errors.New("packer: pipeline is empty")

	// ErrPipelineTooLong fires when the pipeline exceeds 255
	// steps. The wire format encodes step count as one byte;
	// 255 is more than any operator should ever stack.
	ErrPipelineTooLong = errors.New("packer: pipeline exceeds 255 steps")

	// ErrUnsupportedPermutation fires when a step references a
	// Permutation constant this build doesn't implement.
	ErrUnsupportedPermutation = errors.New("packer: unsupported permutation")

	// ErrPipelineKeysMismatch fires when [UnpackPipeline] is
	// called with a `keys` slice whose length disagrees with the
	// blob's recorded pipeline step count.
	ErrPipelineKeysMismatch = errors.New("packer: pipeline keys count mismatch")
)

// PackPipeline applies each step in `opts.Pipeline` to `data`
// in order and emits a maldev-format blob (FormatVersion 2).
// Returns the blob + per-step keys (auto-generated when the
// caller-supplied step.Key is nil).
//
// The wire format records each step's Op + Algo so [UnpackPipeline]
// can reverse the chain, but the keys are NEVER stored in the
// blob — operators transport keys via a separate channel.
func PackPipeline(data []byte, pipeline []PipelineStep) ([]byte, PipelineKeys, error) {
	if len(pipeline) == 0 {
		return nil, nil, ErrEmptyPipeline
	}
	if len(pipeline) > 255 {
		return nil, nil, ErrPipelineTooLong
	}

	current := data
	keys := make(PipelineKeys, len(pipeline))
	for i, step := range pipeline {
		k := step.Key
		out, generatedKey, err := applyStep(step.Op, step.Algo, k, current)
		if err != nil {
			return nil, nil, fmt.Errorf("packer: pipeline step %d (%s/%d): %w", i, step.Op, step.Algo, err)
		}
		current = out
		if k == nil {
			keys[i] = generatedKey
		} else {
			keys[i] = k
		}
	}

	out := make([]byte, headerSizeV2+2*len(pipeline)+len(current))
	(&headerV2{
		Magic:       Magic,
		Version:     FormatVersionPipeline,
		NumSteps:    uint8(len(pipeline)),
		OrigSize:    uint64(len(data)),
		PayloadSize: uint64(len(current)),
	}).marshalInto(out)
	off := headerSizeV2
	for _, s := range pipeline {
		out[off] = uint8(s.Op)
		out[off+1] = s.Algo
		off += 2
	}
	copy(out[off:], current)
	return out, keys, nil
}

// UnpackPipeline reverses [PackPipeline] given the per-step
// keys returned by Pack.
func UnpackPipeline(packed []byte, keys PipelineKeys) ([]byte, error) {
	h, err := unmarshalHeaderV2(packed)
	if err != nil {
		return nil, err
	}
	if int(h.NumSteps) != len(keys) {
		return nil, fmt.Errorf("%w: blob says %d steps, got %d keys",
			ErrPipelineKeysMismatch, h.NumSteps, len(keys))
	}

	tableEnd := headerSizeV2 + 2*int(h.NumSteps)
	if tableEnd > len(packed) {
		return nil, fmt.Errorf("%w: pipeline table past end of blob", ErrBadMagic)
	}
	body := packed[tableEnd:]
	if uint64(len(body)) != h.PayloadSize {
		return nil, fmt.Errorf("%w: header says %d, body is %d",
			ErrPayloadSizeMismatch, h.PayloadSize, len(body))
	}

	current := body
	for i := int(h.NumSteps) - 1; i >= 0; i-- {
		off := headerSizeV2 + 2*i
		op := PipelineOp(packed[off])
		algo := packed[off+1]
		out, err := reverseStep(op, algo, keys[i], current)
		if err != nil {
			return nil, fmt.Errorf("packer: reverse step %d (%s/%d): %w", i, op, algo, err)
		}
		current = out
	}
	if uint64(len(current)) != h.OrigSize {
		return nil, fmt.Errorf("packer: reversed %d bytes, header says %d",
			len(current), h.OrigSize)
	}
	return current, nil
}

// applyStep runs ONE pipeline step forward. Returns the
// transformed bytes + the key used (callers passing key=nil
// get the generated key back). Compression steps return a nil
// key (no secret needed).
func applyStep(op PipelineOp, algo uint8, key, data []byte) (out []byte, usedKey []byte, err error) {
	switch op {
	case OpCipher:
		return applyCipher(Cipher(algo), key, data)
	case OpPermute:
		return applyPermutation(Permutation(algo), key, data)
	case OpCompress:
		return applyCompression(Compressor(algo), data)
	default:
		return nil, nil, fmt.Errorf("unknown op %d", op)
	}
}

// reverseStep runs ONE pipeline step backward.
func reverseStep(op PipelineOp, algo uint8, key, data []byte) ([]byte, error) {
	switch op {
	case OpCipher:
		return reverseCipher(Cipher(algo), key, data)
	case OpPermute:
		return reversePermutation(Permutation(algo), key, data)
	case OpCompress:
		return reverseCompression(Compressor(algo), data)
	default:
		return nil, fmt.Errorf("unknown op %d", op)
	}
}

func applyCipher(c Cipher, key, data []byte) (out []byte, usedKey []byte, err error) {
	switch c {
	case CipherAESGCM:
		if key == nil {
			key, err = crypto.NewAESKey()
			if err != nil {
				return nil, nil, err
			}
		}
		out, err = crypto.EncryptAESGCM(key, data)
		return out, key, err
	case CipherChaCha20:
		if key == nil {
			key, err = crypto.NewChaCha20Key()
			if err != nil {
				return nil, nil, err
			}
		}
		out, err = crypto.EncryptChaCha20(key, data)
		return out, key, err
	case CipherRC4:
		if key == nil {
			key = make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return nil, nil, err
			}
		}
		out, err = crypto.EncryptRC4(key, data)
		return out, key, err
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedCipher, c)
	}
}

func reverseCipher(c Cipher, key, data []byte) ([]byte, error) {
	switch c {
	case CipherAESGCM:
		return crypto.DecryptAESGCM(key, data)
	case CipherChaCha20:
		return crypto.DecryptChaCha20(key, data)
	case CipherRC4:
		// RC4 is its own inverse — Encrypt and Decrypt are the
		// same operation.
		return crypto.EncryptRC4(key, data)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCipher, c)
	}
}

func applyPermutation(p Permutation, key, data []byte) (out []byte, usedKey []byte, err error) {
	switch p {
	case PermutationXOR:
		if key == nil {
			key = make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return nil, nil, err
			}
		}
		out, err = crypto.XORWithRepeatingKey(data, key)
		return out, key, err
	case PermutationArithShift:
		if key == nil {
			key = make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return nil, nil, err
			}
		}
		out, err = crypto.ArithShift(data, key)
		return out, key, err
	case PermutationSBox:
		// S-Box "key" is the concatenation of sbox[256] + inverse[256].
		var sbox, inv [256]byte
		if key == nil {
			sbox, inv, err = crypto.NewSBox()
			if err != nil {
				return nil, nil, err
			}
			key = make([]byte, 512)
			copy(key[:256], sbox[:])
			copy(key[256:], inv[:])
		} else if len(key) != 512 {
			return nil, nil, fmt.Errorf("%w: sbox key must be 512 bytes (sbox+inverse), got %d",
				ErrUnsupportedPermutation, len(key))
		} else {
			copy(sbox[:], key[:256])
			copy(inv[:], key[256:])
		}
		out = crypto.SubstituteBytes(data, sbox)
		return out, key, nil
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedPermutation, p)
	}
}

func reversePermutation(p Permutation, key, data []byte) ([]byte, error) {
	switch p {
	case PermutationXOR:
		return crypto.XORWithRepeatingKey(data, key)
	case PermutationArithShift:
		return crypto.ReverseArithShift(data, key)
	case PermutationSBox:
		if len(key) != 512 {
			return nil, fmt.Errorf("%w: sbox key must be 512 bytes", ErrUnsupportedPermutation)
		}
		var inv [256]byte
		copy(inv[:], key[256:])
		return crypto.ReverseSubstituteBytes(data, inv), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPermutation, p)
	}
}
