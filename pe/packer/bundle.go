package packer

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// Bundle wire format constants.
//
// On-disk layout (all little-endian):
//
//	[BundleHeader               (32 bytes)]
//	[FingerprintEntry × Count   (48 bytes each)]
//	[PayloadEntry × Count       (32 bytes each)]
//	[EncryptedPayloadData × Count (variable, concatenated)]
//
// The bundle header sits at the start of the bundle blob; the binary's
// entry point points into the bundle stub (which lives just past
// EncryptedPayloadData). All offsets in the header are RVAs relative to
// the bundle's first byte.
//
// See docs/superpowers/specs/2026-05-08-packer-multi-target-bundle.md
// for the full design and threat model.
const (
	// BundleMagic is the four-byte ASCII tag at offset 0 — "MLDV".
	BundleMagic uint32 = 0x56444C4D

	// BundleVersion is the wire-format version surfaced in BundleHeader.
	BundleVersion uint16 = 0x0001

	// BundleHeaderSize, BundleFingerprintEntrySize, BundlePayloadEntrySize
	// are the on-disk sizes of each region's entry.
	BundleHeaderSize           = 32
	BundleFingerprintEntrySize = 48
	BundlePayloadEntrySize     = 32

	// BundleMaxPayloads is the practical upper bound on payload count.
	// Wire format allows uint16 (65 535); we cap at 255 per spec to keep
	// the fingerprint-loop stub size sane.
	BundleMaxPayloads = 255
)

// PredicateType bitmask flags for FingerprintPredicate.PredicateType.
//
// Within a single FingerprintEntry, all enabled bits are ANDed: every
// active check must pass for the entry to match. Across entries, the
// first matching entry wins.
const (
	PTCPUIDVendor   uint8 = 1 << 0 // 12-byte CPUID EAX=0 vendor string check
	PTWinBuild      uint8 = 1 << 1 // PEB.OSBuildNumber range check
	PTCPUIDFeatures uint8 = 1 << 2 // CPUID EAX=1 ECX feature mask check
	PTMatchAll      uint8 = 1 << 3 // wildcard — matches any host
)

// BundleFallbackBehaviour controls what the stub does when no
// FingerprintEntry matches the host.
type BundleFallbackBehaviour uint32

const (
	// BundleFallbackExit silently calls ExitProcess(0) / exit(0). Default.
	BundleFallbackExit BundleFallbackBehaviour = 0
	// BundleFallbackCrash deliberately faults to surface a sandbox alert.
	BundleFallbackCrash BundleFallbackBehaviour = 1
	// BundleFallbackFirst selects payload 0 unconditionally. Operator
	// opt-in for dev/test only — defeats the per-host secrecy property.
	BundleFallbackFirst BundleFallbackBehaviour = 2
)

// FingerprintPredicate encodes the host-matching logic for one payload.
//
// PredicateType is a bitmask of PT* constants. Within one predicate all
// enabled checks are ANDed; across predicates the bundle stub picks the
// first matching entry.
type FingerprintPredicate struct {
	PredicateType uint8

	// VendorString is the 12-byte CPUID vendor to match. Zero/empty means
	// wildcard (any vendor). Only consulted when PTCPUIDVendor is set.
	VendorString [12]byte

	// BuildMin and BuildMax form an inclusive Windows build-number range.
	// Zero on either end means "no bound on this side". Only consulted
	// when PTWinBuild is set.
	BuildMin uint32
	BuildMax uint32

	// CPUIDFeatureMask + CPUIDFeatureValue check
	// (CPUID[1].ECX & Mask) == Value. Mask=0 skips the check.
	CPUIDFeatureMask  uint32
	CPUIDFeatureValue uint32

	// Negate inverts the entire predicate match outcome.
	Negate bool
}

// BundlePayload is one payload binary paired with its fingerprint
// predicate and the per-payload pack options.
type BundlePayload struct {
	// Binary is the original PE/ELF bytes to embed.
	Binary []byte
	// Fingerprint is the host-matching rule for this payload.
	Fingerprint FingerprintPredicate
}

// BundleOptions parameterises [PackBinaryBundle].
type BundleOptions struct {
	// FallbackBehaviour selects the action when no predicate matches.
	FallbackBehaviour BundleFallbackBehaviour
	// CipherKey is the per-payload XOR key. When nil, a fresh random
	// 16-byte key is generated for each payload. The same key is reused
	// across payloads when caller-supplied (test determinism only — in
	// production let it stay nil for per-payload keys).
	CipherKey []byte
}

// Sentinels surfaced by [PackBinaryBundle].
var (
	// ErrEmptyBundle fires when payloads is nil or has zero length.
	ErrEmptyBundle = errors.New("packer: empty bundle")
	// ErrBundleTooLarge fires when len(payloads) exceeds BundleMaxPayloads.
	ErrBundleTooLarge = errors.New("packer: bundle exceeds 255 payloads")
)

// PackBinaryBundle packs N payload binaries into a single multi-target
// bundle blob. Phase P1 (v0.67.0-alpha.1): wire-format-only — the bundle
// is a flat byte slice in spec layout, with each payload XOR-encrypted
// with its own key. The stub-side fingerprint evaluator and PE/ELF
// container injection ship in subsequent phases.
//
// Returns the serialised bundle bytes. The caller is responsible for
// wrapping the bundle in a PE/ELF container — see [PackBinary] for the
// single-payload equivalent and the spec's §5 Stub Flow for the eventual
// multi-payload entry point.
//
// Errors: [ErrEmptyBundle], [ErrBundleTooLarge], plus crypto/rand
// failures wrapping when CipherKey is nil.
func PackBinaryBundle(payloads []BundlePayload, opts BundleOptions) ([]byte, error) {
	if len(payloads) == 0 {
		return nil, ErrEmptyBundle
	}
	if len(payloads) > BundleMaxPayloads {
		return nil, fmt.Errorf("%w: %d > %d", ErrBundleTooLarge, len(payloads), BundleMaxPayloads)
	}

	count := uint16(len(payloads))
	fpTableOff := uint32(BundleHeaderSize)
	plTableOff := fpTableOff + uint32(count)*BundleFingerprintEntrySize
	dataOff := plTableOff + uint32(count)*BundlePayloadEntrySize

	// Encrypt each payload up front so we know the ciphertext sizes
	// (XOR is size-preserving but factor out for future cipher swaps).
	type encrypted struct {
		bytes []byte
		key   [16]byte
		plain uint32
	}
	encs := make([]encrypted, count)
	cursor := dataOff
	for i, p := range payloads {
		var key [16]byte
		if opts.CipherKey != nil {
			copy(key[:], opts.CipherKey)
		} else if _, err := rand.Read(key[:]); err != nil {
			return nil, fmt.Errorf("packer: bundle key %d: %w", i, err)
		}
		ct := make([]byte, len(p.Binary))
		for j := range p.Binary {
			ct[j] = p.Binary[j] ^ key[j%16]
		}
		encs[i] = encrypted{bytes: ct, key: key, plain: uint32(len(p.Binary))}
		cursor += uint32(len(ct))
	}

	out := make([]byte, dataOff)

	// BundleHeader (32 bytes).
	binary.LittleEndian.PutUint32(out[0:4], BundleMagic)
	binary.LittleEndian.PutUint16(out[4:6], BundleVersion)
	binary.LittleEndian.PutUint16(out[6:8], count)
	binary.LittleEndian.PutUint32(out[8:12], fpTableOff)
	binary.LittleEndian.PutUint32(out[12:16], plTableOff)
	binary.LittleEndian.PutUint32(out[16:20], dataOff)
	binary.LittleEndian.PutUint32(out[20:24], uint32(opts.FallbackBehaviour))
	// Reserved [24:32] left zero by make.

	// FingerprintEntry × N.
	for i, p := range payloads {
		off := int(fpTableOff) + i*BundleFingerprintEntrySize
		out[off] = p.Fingerprint.PredicateType
		if p.Fingerprint.Negate {
			out[off+1] = 1
		}
		copy(out[off+4:off+16], p.Fingerprint.VendorString[:])
		binary.LittleEndian.PutUint32(out[off+16:off+20], p.Fingerprint.BuildMin)
		binary.LittleEndian.PutUint32(out[off+20:off+24], p.Fingerprint.BuildMax)
		binary.LittleEndian.PutUint32(out[off+24:off+28], p.Fingerprint.CPUIDFeatureMask)
		binary.LittleEndian.PutUint32(out[off+28:off+32], p.Fingerprint.CPUIDFeatureValue)
		// Reserved2 [off+32:off+48] left zero.
	}

	// PayloadEntry × N.
	dataCursor := dataOff
	for i, e := range encs {
		off := int(plTableOff) + i*BundlePayloadEntrySize
		binary.LittleEndian.PutUint32(out[off:off+4], dataCursor)
		binary.LittleEndian.PutUint32(out[off+4:off+8], uint32(len(e.bytes)))
		binary.LittleEndian.PutUint32(out[off+8:off+12], e.plain)
		out[off+12] = 1 // CipherType = XOR-rolling (16-byte key)
		// off+13..off+16 reserved
		copy(out[off+16:off+32], e.key[:])
		dataCursor += uint32(len(e.bytes))
	}

	// EncryptedPayloadData (concatenated).
	for _, e := range encs {
		out = append(out, e.bytes...)
	}

	return out, nil
}

// SelectPayload is the pure-Go reference implementation of the bundle
// stub's fingerprint-matching logic. Given a bundle blob and the host's
// CPUID vendor + Windows build number, it returns the index of the first
// FingerprintEntry whose predicate matches, or -1 if none does.
//
// Matching logic per spec §3.4:
//   - PT_MATCH_ALL (bit 3): always matches.
//   - Otherwise, every set bit in PredicateType must pass:
//     - PT_CPUID_VENDOR: VendorString == hostVendor (or all-zero wildcard)
//     - PT_WIN_BUILD: BuildMin <= hostBuild <= BuildMax
//       (zero on either bound means no bound on that side)
//     - PT_CPUID_FEATURES: not consulted by SelectPayload — caller would
//       supply the feature ECX value separately; deferred until needed.
//   - Negate flag inverts the entire entry's match outcome.
//
// On no match, the caller applies FallbackBehaviour from the header.
//
// The asm evaluator emitted in C6-P3 mirrors this logic byte-for-byte
// (excepting the feature-mask branch). Tests in bundle_test.go assert
// SelectPayload and the asm produce identical indices for matched
// vendor/build combinations.
func SelectPayload(bundle []byte, hostVendor [12]byte, hostBuild uint32) (int, error) {
	if len(bundle) < BundleHeaderSize {
		return -1, fmt.Errorf("packer: bundle truncated (%d < %d)", len(bundle), BundleHeaderSize)
	}
	if magic := binary.LittleEndian.Uint32(bundle[0:4]); magic != BundleMagic {
		return -1, fmt.Errorf("packer: bundle magic %#x != %#x", magic, BundleMagic)
	}
	count := int(binary.LittleEndian.Uint16(bundle[6:8]))
	fpTableOff := int(binary.LittleEndian.Uint32(bundle[8:12]))
	if fpTableOff+count*BundleFingerprintEntrySize > len(bundle) {
		return -1, fmt.Errorf("packer: fingerprint table outside blob")
	}

	for i := 0; i < count; i++ {
		off := fpTableOff + i*BundleFingerprintEntrySize
		predType := bundle[off]
		negate := bundle[off+1]&0x01 != 0

		match := evaluateEntry(bundle[off:off+BundleFingerprintEntrySize], hostVendor, hostBuild)
		if predType&PTMatchAll != 0 {
			match = true
		}
		if negate {
			match = !match
		}
		if match {
			return i, nil
		}
	}
	return -1, nil
}

// evaluateEntry runs the AND-combined predicate checks for one
// FingerprintEntry slice. Caller has already verified the slice is at
// least BundleFingerprintEntrySize bytes long.
func evaluateEntry(entry []byte, hostVendor [12]byte, hostBuild uint32) bool {
	predType := entry[0]
	if predType == 0 {
		// No checks set — empty predicate matches nothing (use PTMatchAll
		// for "always match"). Defensive: prevents accidental wide matches.
		return false
	}

	if predType&PTCPUIDVendor != 0 {
		var want [12]byte
		copy(want[:], entry[4:16])
		if want != [12]byte{} && want != hostVendor {
			return false
		}
	}
	if predType&PTWinBuild != 0 {
		bMin := binary.LittleEndian.Uint32(entry[16:20])
		bMax := binary.LittleEndian.Uint32(entry[20:24])
		if bMin != 0 && hostBuild < bMin {
			return false
		}
		if bMax != 0 && hostBuild > bMax {
			return false
		}
	}
	// PTCPUIDFeatures — caller-supplied ECX not threaded through this
	// signature; once added, AND a (hostECX & mask) == value check here.
	return true
}

// UnpackBundle is the host-side inverse of [PackBinaryBundle]: it parses a
// bundle blob, locates the payload at index `idx`, and decrypts it using
// the on-disk key.
//
// This is a debugging / build-host helper. The runtime stub (shipped in
// later phases) re-implements the same logic in asm and never exposes
// keys to memory unless its predicate matched.
func UnpackBundle(bundle []byte, idx int) ([]byte, error) {
	if len(bundle) < BundleHeaderSize {
		return nil, fmt.Errorf("packer: bundle truncated (%d < header %d)", len(bundle), BundleHeaderSize)
	}
	if magic := binary.LittleEndian.Uint32(bundle[0:4]); magic != BundleMagic {
		return nil, fmt.Errorf("packer: bundle magic %#x != %#x", magic, BundleMagic)
	}
	count := binary.LittleEndian.Uint16(bundle[6:8])
	if idx < 0 || idx >= int(count) {
		return nil, fmt.Errorf("packer: bundle index %d out of range [0, %d)", idx, count)
	}
	plTableOff := binary.LittleEndian.Uint32(bundle[12:16])
	entryOff := int(plTableOff) + idx*BundlePayloadEntrySize
	if entryOff+BundlePayloadEntrySize > len(bundle) {
		return nil, fmt.Errorf("packer: bundle PayloadEntry %d outside blob", idx)
	}
	dataRVA := binary.LittleEndian.Uint32(bundle[entryOff : entryOff+4])
	dataSize := binary.LittleEndian.Uint32(bundle[entryOff+4 : entryOff+8])
	if int(dataRVA)+int(dataSize) > len(bundle) {
		return nil, fmt.Errorf("packer: bundle payload %d data outside blob", idx)
	}
	var key [16]byte
	copy(key[:], bundle[entryOff+16:entryOff+32])
	ct := bundle[dataRVA : dataRVA+dataSize]
	pt := make([]byte, len(ct))
	for j := range ct {
		pt[j] = ct[j] ^ key[j%16]
	}
	return pt, nil
}
