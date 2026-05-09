package packer_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestVendorConstants_Shape pins the canonical vendor-string byte
// values exported by the package. Defenders / operators referencing
// VendorIntel etc. expect these EXACT bytes — drift would silently
// break every fingerprint predicate that depends on them.
func TestVendorConstants_Shape(t *testing.T) {
	cases := []struct {
		name string
		got  [12]byte
		want string
	}{
		{"Intel", packer.VendorIntel, "GenuineIntel"},
		{"AMD", packer.VendorAMD, "AuthenticAMD"},
		{"Hygon", packer.VendorHygon, "HygonGenuine"},
	}
	for _, c := range cases {
		if string(c.got[:]) != c.want {
			t.Errorf("Vendor%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// TestPackBinaryBundle_EmptyPayloads asserts the [packer.ErrEmptyBundle]
// sentinel surfaces for nil + zero-length inputs.
func TestPackBinaryBundle_EmptyPayloads(t *testing.T) {
	for _, p := range [][]packer.BundlePayload{nil, {}} {
		_, err := packer.PackBinaryBundle(p, packer.BundleOptions{})
		if !errors.Is(err, packer.ErrEmptyBundle) {
			t.Errorf("PackBinaryBundle(empty) err = %v, want ErrEmptyBundle", err)
		}
	}
}

// TestPackBinaryBundle_TooLarge asserts the bundle rejects > 255 payloads.
func TestPackBinaryBundle_TooLarge(t *testing.T) {
	huge := make([]packer.BundlePayload, packer.BundleMaxPayloads+1)
	for i := range huge {
		huge[i] = packer.BundlePayload{Binary: []byte("x")}
	}
	_, err := packer.PackBinaryBundle(huge, packer.BundleOptions{})
	if !errors.Is(err, packer.ErrBundleTooLarge) {
		t.Errorf("PackBinaryBundle(256) err = %v, want ErrBundleTooLarge", err)
	}
}

// TestPackBinaryBundle_HeaderLayout asserts the BundleHeader fields are
// serialised at their spec offsets.
func TestPackBinaryBundle_HeaderLayout(t *testing.T) {
	out, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("hello")}},
		packer.BundleOptions{
			FallbackBehaviour: packer.BundleFallbackCrash,
			FixedKey:         bytes.Repeat([]byte{0xAA}, 16),
		},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	if len(out) < packer.BundleHeaderSize {
		t.Fatalf("output truncated: %d < %d", len(out), packer.BundleHeaderSize)
	}

	if got := binary.LittleEndian.Uint32(out[0:4]); got != packer.BundleMagic {
		t.Errorf("magic = %#x, want %#x", got, packer.BundleMagic)
	}
	if got := binary.LittleEndian.Uint16(out[4:6]); got != packer.BundleVersion {
		t.Errorf("version = %#x, want %#x", got, packer.BundleVersion)
	}
	if got := binary.LittleEndian.Uint16(out[6:8]); got != 1 {
		t.Errorf("count = %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint32(out[8:12]); got != packer.BundleHeaderSize {
		t.Errorf("FpTableOffset = %d, want %d", got, packer.BundleHeaderSize)
	}
	if got := binary.LittleEndian.Uint32(out[20:24]); got != uint32(packer.BundleFallbackCrash) {
		t.Errorf("FallbackBehaviour = %d, want %d", got, packer.BundleFallbackCrash)
	}
	// Reserved [24:32] must be zero.
	for i := 24; i < 32; i++ {
		if out[i] != 0 {
			t.Errorf("Reserved byte %d = %#x, want 0", i, out[i])
		}
	}
}

// TestPackBinaryBundle_FingerprintRoundTrip verifies a FingerprintPredicate
// is serialised at the right entry slot and round-trips field-for-field.
func TestPackBinaryBundle_FingerprintRoundTrip(t *testing.T) {
	pred := packer.FingerprintPredicate{
		PredicateType:     packer.PTCPUIDVendor | packer.PTWinBuild,
		VendorString:      packer.VendorIntel,
		BuildMin:          22000,
		BuildMax:          22631,
		CPUIDFeatureMask:  0xff,
		CPUIDFeatureValue: 0x42,
		Negate:            true,
	}
	out, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("p"), Fingerprint: pred}},
		packer.BundleOptions{FixedKey: make([]byte, 16)},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	off := packer.BundleHeaderSize
	if got := out[off]; got != pred.PredicateType {
		t.Errorf("PredicateType = %#x, want %#x", got, pred.PredicateType)
	}
	if got := out[off+1]; got != 1 { // Negate flag bit 0
		t.Errorf("Flags = %#x, want 0x01 (negate)", got)
	}
	if got := string(out[off+4 : off+16]); got != string(pred.VendorString[:]) {
		t.Errorf("VendorString = %q, want %q", got, pred.VendorString)
	}
	if got := binary.LittleEndian.Uint32(out[off+16 : off+20]); got != pred.BuildMin {
		t.Errorf("BuildMin = %d, want %d", got, pred.BuildMin)
	}
	if got := binary.LittleEndian.Uint32(out[off+20 : off+24]); got != pred.BuildMax {
		t.Errorf("BuildMax = %d, want %d", got, pred.BuildMax)
	}
	if got := binary.LittleEndian.Uint32(out[off+24 : off+28]); got != pred.CPUIDFeatureMask {
		t.Errorf("CPUIDFeatureMask = %#x, want %#x", got, pred.CPUIDFeatureMask)
	}
	if got := binary.LittleEndian.Uint32(out[off+28 : off+32]); got != pred.CPUIDFeatureValue {
		t.Errorf("CPUIDFeatureValue = %#x, want %#x", got, pred.CPUIDFeatureValue)
	}
}

// TestUnpackBundle_RoundTripsTwoPayloads verifies the host-side helper
// UnpackBundle decrypts each entry independently and yields the original
// payload bytes.
func TestUnpackBundle_RoundTripsTwoPayloads(t *testing.T) {
	pls := []packer.BundlePayload{
		{Binary: []byte("payload-AMD-23H2-message"),
			Fingerprint: packer.FingerprintPredicate{PredicateType: packer.PTMatchAll}},
		{Binary: bytes.Repeat([]byte{0xAB}, 4096),
			Fingerprint: packer.FingerprintPredicate{PredicateType: packer.PTMatchAll}},
	}
	out, err := packer.PackBinaryBundle(pls, packer.BundleOptions{})
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	for i, p := range pls {
		got, err := packer.UnpackBundle(out, i)
		if err != nil {
			t.Fatalf("UnpackBundle(%d): %v", i, err)
		}
		if !bytes.Equal(got, p.Binary) {
			t.Errorf("payload %d: got %d bytes, want %d", i, len(got), len(p.Binary))
		}
	}
}

// TestUnpackBundle_RejectsBadInputs covers truncated blobs, wrong magic,
// out-of-range index — all surfacing wrapped errors.
func TestUnpackBundle_RejectsBadInputs(t *testing.T) {
	good, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("x")}},
		packer.BundleOptions{FixedKey: make([]byte, 16)},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	cases := []struct {
		name    string
		input   []byte
		idx     int
		wantSub string
	}{
		{"truncated", []byte{0x4D, 0x4C}, 0, "truncated"},
		{"badMagic", append(append([]byte(nil), make([]byte, 32)...)), 0, "magic"},
		{"idxNeg", good, -1, "out of range"},
		{"idxHigh", good, 5, "out of range"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := packer.UnpackBundle(c.input, c.idx)
			if err == nil {
				t.Fatalf("UnpackBundle: want error, got nil")
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("err %v does not contain %q", err, c.wantSub)
			}
		})
	}
}

// TestInspectBundle_RoundTripsHeaderAndEntries verifies InspectBundle
// extracts every wire-format field for a 2-payload bundle.
func TestInspectBundle_RoundTripsHeaderAndEntries(t *testing.T) {
	intel := packer.VendorIntel
	pls := []packer.BundlePayload{
		{Binary: []byte("intel"), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTCPUIDVendor,
			VendorString:  intel,
			BuildMin:      22000,
			BuildMax:      22631,
		}},
		{Binary: bytes.Repeat([]byte{0xCC}, 1024), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTMatchAll,
		}},
	}
	bundle, err := packer.PackBinaryBundle(pls, packer.BundleOptions{
		FallbackBehaviour: packer.BundleFallbackCrash,
	})
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	info, err := packer.InspectBundle(bundle)
	if err != nil {
		t.Fatalf("InspectBundle: %v", err)
	}
	if info.Magic != packer.BundleMagic {
		t.Errorf("Magic = %#x, want %#x", info.Magic, packer.BundleMagic)
	}
	if info.Count != 2 {
		t.Errorf("Count = %d, want 2", info.Count)
	}
	if info.FallbackBehaviour != packer.BundleFallbackCrash {
		t.Errorf("FallbackBehaviour = %d, want %d", info.FallbackBehaviour, packer.BundleFallbackCrash)
	}
	if got := len(info.Entries); got != 2 {
		t.Fatalf("len(Entries) = %d, want 2", got)
	}

	e0 := info.Entries[0]
	if e0.PredicateType != packer.PTCPUIDVendor {
		t.Errorf("Entries[0].PredicateType = %#x, want %#x", e0.PredicateType, packer.PTCPUIDVendor)
	}
	if e0.VendorString != intel {
		t.Errorf("Entries[0].VendorString = %q, want %q", e0.VendorString, intel)
	}
	if e0.BuildMin != 22000 || e0.BuildMax != 22631 {
		t.Errorf("Entries[0] build = [%d, %d], want [22000, 22631]", e0.BuildMin, e0.BuildMax)
	}
	if e0.PlaintextSize != uint32(len(pls[0].Binary)) {
		t.Errorf("Entries[0].PlaintextSize = %d, want %d", e0.PlaintextSize, len(pls[0].Binary))
	}

	e1 := info.Entries[1]
	if e1.PredicateType != packer.PTMatchAll {
		t.Errorf("Entries[1].PredicateType = %#x, want PTMatchAll", e1.PredicateType)
	}
	if e1.PlaintextSize != 1024 {
		t.Errorf("Entries[1].PlaintextSize = %d, want 1024", e1.PlaintextSize)
	}

	// Decrypting via the parsed Key matches the original payload.
	for i, p := range pls {
		ct := bundle[info.Entries[i].DataRVA : info.Entries[i].DataRVA+info.Entries[i].DataSize]
		pt := make([]byte, len(ct))
		for j := range ct {
			pt[j] = ct[j] ^ info.Entries[i].Key[j%16]
		}
		if !bytes.Equal(pt, p.Binary) {
			t.Errorf("entry %d: decrypted %d bytes, want %d", i, len(pt), len(p.Binary))
		}
	}
}

// TestInspectBundle_RejectsBadInputs covers the three sentinels
// ErrBundleTruncated / ErrBundleBadMagic / ErrBundleOutOfRange.
func TestInspectBundle_RejectsBadInputs(t *testing.T) {
	good, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("x")}},
		packer.BundleOptions{FixedKey: make([]byte, 16)},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	t.Run("truncated", func(t *testing.T) {
		_, err := packer.InspectBundle(good[:8])
		if !errors.Is(err, packer.ErrBundleTruncated) {
			t.Errorf("err = %v, want ErrBundleTruncated", err)
		}
	})
	t.Run("badMagic", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[0] = 0xFF
		_, err := packer.InspectBundle(bad)
		if !errors.Is(err, packer.ErrBundleBadMagic) {
			t.Errorf("err = %v, want ErrBundleBadMagic", err)
		}
	})
	t.Run("dataOutOfRange", func(t *testing.T) {
		// Zero out the trailing payload bytes so DataRVA+DataSize escapes
		// the blob: shrink the slice by 1 byte (last payload byte gone).
		_, err := packer.InspectBundle(good[:len(good)-1])
		if !errors.Is(err, packer.ErrBundleOutOfRange) {
			t.Errorf("err = %v, want ErrBundleOutOfRange", err)
		}
	})
}

// TestSelectPayload_PicksFirstMatch verifies the per-spec selection
// semantics — PT_CPUID_VENDOR + PT_WIN_BUILD AND-combined; first-match
// wins; PT_MATCH_ALL acts as a default; Negate inverts.
func TestSelectPayload_PicksFirstMatch(t *testing.T) {
	intel := packer.VendorIntel
	amd := packer.VendorAMD

	pls := []packer.BundlePayload{
		{Binary: []byte("intel-w11"), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTCPUIDVendor | packer.PTWinBuild,
			VendorString:  intel,
			BuildMin:      22000,
			BuildMax:      99999,
		}},
		{Binary: []byte("amd-w10"), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTCPUIDVendor | packer.PTWinBuild,
			VendorString:  amd,
			BuildMin:      10000,
			BuildMax:      19999,
		}},
		{Binary: []byte("fallback"), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTMatchAll,
		}},
	}
	bundle, err := packer.PackBinaryBundle(pls, packer.BundleOptions{})
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	cases := []struct {
		name   string
		vendor [12]byte
		build  uint32
		want   int
	}{
		{"intelWin11", intel, 22631, 0},
		{"amdWin10", amd, 19041, 1},
		{"intelWin10", intel, 19041, 2},   // intel build out of range → fallback
		{"unknownVendor", [12]byte{}, 100, 2}, // → PTMatchAll
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := packer.SelectPayload(bundle, c.vendor, c.build)
			if err != nil {
				t.Fatalf("SelectPayload: %v", err)
			}
			if got != c.want {
				t.Errorf("SelectPayload = %d, want %d", got, c.want)
			}
		})
	}
}

// TestSelectPayload_NegateInverts asserts the Flags.Negate bit reverses
// an entry's match outcome.
func TestSelectPayload_NegateInverts(t *testing.T) {
	intel := packer.VendorIntel
	pls := []packer.BundlePayload{
		// Negated Intel: matches anything that is NOT Intel.
		{Binary: []byte("non-intel"), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTCPUIDVendor,
			VendorString:  intel,
			Negate:        true,
		}},
	}
	bundle, _ := packer.PackBinaryBundle(pls, packer.BundleOptions{})

	idx, _ := packer.SelectPayload(bundle, packer.VendorAMD, 0)
	if idx != 0 {
		t.Errorf("AMD against !Intel: got %d, want 0", idx)
	}
	idx, _ = packer.SelectPayload(bundle, intel, 0)
	if idx != -1 {
		t.Errorf("Intel against !Intel: got %d, want -1 (no match)", idx)
	}
}

// TestSelectPayload_NoMatchReturnsMinusOne asserts -1 + nil error when no
// entry matches and there's no PTMatchAll catch-all.
func TestSelectPayload_NoMatchReturnsMinusOne(t *testing.T) {
	pls := []packer.BundlePayload{
		{Binary: []byte("x"), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTWinBuild, BuildMin: 10000, BuildMax: 20000,
		}},
	}
	bundle, _ := packer.PackBinaryBundle(pls, packer.BundleOptions{})
	got, err := packer.SelectPayload(bundle, [12]byte{}, 99999)
	if err != nil {
		t.Fatalf("SelectPayload: %v", err)
	}
	if got != -1 {
		t.Errorf("got %d, want -1", got)
	}
}

// TestDeriveBundleProfile_Empty asserts the zero-secret case
// returns the canonical magic + footer pair so existing callers
// without a -secret flag stay wire-compatible with the spec.
func TestDeriveBundleProfile_Empty(t *testing.T) {
	for _, in := range [][]byte{nil, {}} {
		p := packer.DeriveBundleProfile(in)
		if p.Magic != packer.BundleMagic {
			t.Errorf("DeriveBundleProfile(empty) Magic = %#x, want %#x", p.Magic, packer.BundleMagic)
		}
		if p.FooterMagic != packer.BundleFooterMagic {
			t.Errorf("DeriveBundleProfile(empty) FooterMagic = %q, want %q",
				p.FooterMagic, packer.BundleFooterMagic)
		}
	}
}

// TestDeriveBundleProfile_Deterministic asserts the SHA-256-derived
// profile is stable for a given secret.
func TestDeriveBundleProfile_Deterministic(t *testing.T) {
	secret := []byte("ops-cycle-2026-05-deployment-A")
	a := packer.DeriveBundleProfile(secret)
	b := packer.DeriveBundleProfile(secret)
	if a != b {
		t.Errorf("DeriveBundleProfile drifted: %+v vs %+v", a, b)
	}
	if a.Magic == packer.BundleMagic {
		t.Errorf("non-empty secret produced canonical magic — derivation broken")
	}
}

// TestDeriveBundleProfile_DifferentSecretsDistinct asserts two
// distinct secrets yield distinct profiles (collision-resistant via
// SHA-256).
func TestDeriveBundleProfile_DifferentSecretsDistinct(t *testing.T) {
	a := packer.DeriveBundleProfile([]byte("alpha"))
	b := packer.DeriveBundleProfile([]byte("bravo"))
	if a.Magic == b.Magic {
		t.Errorf("same magic for different secrets: %#x", a.Magic)
	}
	if a.FooterMagic == b.FooterMagic {
		t.Errorf("same footer for different secrets")
	}
}

// TestPackBinaryBundle_HonoursProfileVersion asserts the
// per-build Version byte at offset 4 of the bundle header is the
// operator-chosen value (derived via SHA-256), not the canonical
// 0x0001 — defenders matching "version field == 1" must miss
// every -secret-built artefact.
func TestPackBinaryBundle_HonoursProfileVersion(t *testing.T) {
	profile := packer.DeriveBundleProfile([]byte("kerckhoffs-version"))
	if profile.Version == packer.BundleVersion {
		t.Fatalf("derived Version = canonical %#x — derivation broken", profile.Version)
	}
	out, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("p")}},
		packer.BundleOptions{Profile: profile},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	if got := binary.LittleEndian.Uint16(out[4:6]); got != profile.Version {
		t.Errorf("version in blob = %#x, want %#x", got, profile.Version)
	}
	if got := binary.LittleEndian.Uint16(out[4:6]); got == packer.BundleVersion {
		t.Errorf("blob still carries canonical version — profile.Version ignored")
	}
}

// TestPackBinaryBundle_HonoursProfileMagic verifies the bundle blob
// carries the operator-chosen Magic at offset 0 instead of the
// canonical BundleMagic.
func TestPackBinaryBundle_HonoursProfileMagic(t *testing.T) {
	profile := packer.DeriveBundleProfile([]byte("kerckhoffs"))
	out, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("p")}},
		packer.BundleOptions{Profile: profile},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	got := binary.LittleEndian.Uint32(out[0:4])
	if got != profile.Magic {
		t.Errorf("magic in blob = %#x, want %#x (canonical was %#x)",
			got, profile.Magic, packer.BundleMagic)
	}
	if got == packer.BundleMagic {
		t.Errorf("blob still carries canonical magic — profile ignored")
	}
}

// TestAppendBundleWith_RoundTripsViaExtractWith asserts the
// per-build footer round-trips and a canonical extract REJECTS the
// per-build footer (proves the magic gate).
func TestAppendBundleWith_RoundTripsViaExtractWith(t *testing.T) {
	profile := packer.DeriveBundleProfile([]byte("deploy-secret-42"))
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("payload")}},
		packer.BundleOptions{Profile: profile},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	launcher := bytes.Repeat([]byte{0x90}, 1024)
	wrapped := packer.AppendBundleWith(launcher, bundle, profile)

	got, err := packer.ExtractBundleWith(wrapped, profile)
	if err != nil {
		t.Fatalf("ExtractBundleWith: %v", err)
	}
	if !bytes.Equal(got, bundle) {
		t.Errorf("extracted bundle != original (%d vs %d bytes)", len(got), len(bundle))
	}

	// Canonical ExtractBundle should REFUSE the per-build footer.
	if _, err := packer.ExtractBundle(wrapped); !errors.Is(err, packer.ErrBundleBadMagic) {
		t.Errorf("canonical Extract on per-build wrap: err = %v, want ErrBundleBadMagic", err)
	}
}

// TestSelectPayloadWith_PerBuildMagic asserts the *With variant
// matches against a per-build magic and the canonical SelectPayload
// rejects the same blob with ErrBundleBadMagic.
func TestSelectPayloadWith_PerBuildMagic(t *testing.T) {
	profile := packer.DeriveBundleProfile([]byte("op-2026"))
	bundle, _ := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: []byte("x"),
			Fingerprint: packer.FingerprintPredicate{PredicateType: packer.PTMatchAll},
		}},
		packer.BundleOptions{Profile: profile},
	)

	idx, err := packer.SelectPayloadWith(bundle, profile, [12]byte{}, 0)
	if err != nil {
		t.Fatalf("SelectPayloadWith: %v", err)
	}
	if idx != 0 {
		t.Errorf("SelectPayloadWith idx = %d, want 0", idx)
	}

	if _, err := packer.SelectPayload(bundle, [12]byte{}, 0); !errors.Is(err, packer.ErrBundleBadMagic) {
		t.Errorf("canonical SelectPayload on per-build blob: err = %v, want ErrBundleBadMagic", err)
	}
}

// TestInspectBundleWith_PerBuildMagic asserts InspectBundleWith
// parses a per-build blob whose canonical-Inspect call would have
// failed with ErrBundleBadMagic.
func TestInspectBundleWith_PerBuildMagic(t *testing.T) {
	profile := packer.DeriveBundleProfile([]byte("inspect-test"))
	bundle, _ := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("payload")}},
		packer.BundleOptions{Profile: profile, FixedKey: make([]byte, 16)},
	)

	info, err := packer.InspectBundleWith(bundle, profile)
	if err != nil {
		t.Fatalf("InspectBundleWith: %v", err)
	}
	if info.Magic != profile.Magic {
		t.Errorf("info.Magic = %#x, want %#x", info.Magic, profile.Magic)
	}
	if info.Count != 1 {
		t.Errorf("info.Count = %d, want 1", info.Count)
	}

	if _, err := packer.InspectBundle(bundle); !errors.Is(err, packer.ErrBundleBadMagic) {
		t.Errorf("canonical InspectBundle on per-build blob: err = %v, want ErrBundleBadMagic", err)
	}
}

// TestKerckhoffs_FullRoundTrip is the end-to-end story: per-build
// secret → derive profile → pack with profile → wrap with profile
// → extract with profile → inspect + select + unpack with profile →
// recover the original payload bytes. AND: every parser call without
// the profile must REJECT with ErrBundleBadMagic.
//
// This is the gate test for the Kerckhoffs property — operator's
// secret IS the only thing distinguishing identical operations
// across deployments.
func TestKerckhoffs_FullRoundTrip(t *testing.T) {
	const opSecret = "deploy-cycle-2026-05-09-target-A"
	profile := packer.DeriveBundleProfile([]byte(opSecret))
	plain := []byte("the-real-payload-bytes-here")

	// Pack with profile.
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary:      plain,
			Fingerprint: packer.FingerprintPredicate{PredicateType: packer.PTMatchAll},
		}},
		packer.BundleOptions{Profile: profile, FixedKey: make([]byte, 16)},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	// Wrap with same profile.
	launcher := bytes.Repeat([]byte{0xCC}, 256)
	wrapped := packer.AppendBundleWith(launcher, bundle, profile)

	// Extract with same profile.
	extracted, err := packer.ExtractBundleWith(wrapped, profile)
	if err != nil {
		t.Fatalf("ExtractBundleWith: %v", err)
	}
	if !bytes.Equal(extracted, bundle) {
		t.Fatalf("ExtractBundleWith returned %d bytes, expected %d", len(extracted), len(bundle))
	}

	// Inspect + select + unpack with same profile.
	if _, err := packer.InspectBundleWith(extracted, profile); err != nil {
		t.Fatalf("InspectBundleWith: %v", err)
	}
	idx, err := packer.SelectPayloadWith(extracted, profile, [12]byte{}, 0)
	if err != nil || idx != 0 {
		t.Fatalf("SelectPayloadWith: idx=%d err=%v", idx, err)
	}
	got, err := packer.UnpackBundleWith(extracted, idx, profile)
	if err != nil {
		t.Fatalf("UnpackBundleWith: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("recovered = %q, want %q", got, plain)
	}

	// Negative: every canonical-API call should REFUSE the per-build blob.
	for name, fn := range map[string]func() error{
		"ExtractBundle":  func() error { _, e := packer.ExtractBundle(wrapped); return e },
		"InspectBundle":  func() error { _, e := packer.InspectBundle(extracted); return e },
		"SelectPayload":  func() error { _, e := packer.SelectPayload(extracted, [12]byte{}, 0); return e },
		"UnpackBundle":   func() error { _, e := packer.UnpackBundle(extracted, 0); return e },
	} {
		if err := fn(); !errors.Is(err, packer.ErrBundleBadMagic) {
			t.Errorf("canonical %s on per-build artefact: err = %v, want ErrBundleBadMagic", name, err)
		}
	}
}

// TestUnpackBundleWith_RoundTrip asserts payload bytes survive a
// per-build pack → UnpackBundleWith.
func TestUnpackBundleWith_RoundTrip(t *testing.T) {
	profile := packer.DeriveBundleProfile([]byte("deploy"))
	plain := []byte("the-secret-payload-content")
	bundle, _ := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: plain}},
		packer.BundleOptions{Profile: profile},
	)
	got, err := packer.UnpackBundleWith(bundle, 0, profile)
	if err != nil {
		t.Fatalf("UnpackBundleWith: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("decrypted = %q, want %q", got, plain)
	}
}

// TestAppendBundle_RoundTripsViaExtract concatenates a synthetic
// "launcher" prefix with a real bundle and asserts ExtractBundle
// returns byte-equal bundle bytes.
func TestAppendBundle_RoundTripsViaExtract(t *testing.T) {
	launcher := bytes.Repeat([]byte{0x90}, 1024) // ELF/PE-shaped placeholder
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("payload")}},
		packer.BundleOptions{FixedKey: make([]byte, 16)},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	wrapped := packer.AppendBundle(launcher, bundle)
	if want := len(launcher) + len(bundle) + 16; len(wrapped) != want {
		t.Errorf("len(wrapped) = %d, want %d (launcher + bundle + 16-byte footer)",
			len(wrapped), want)
	}

	got, err := packer.ExtractBundle(wrapped)
	if err != nil {
		t.Fatalf("ExtractBundle: %v", err)
	}
	if !bytes.Equal(got, bundle) {
		t.Errorf("extracted bundle != original (%d vs %d bytes)", len(got), len(bundle))
	}

	// Footer magic at the very end.
	footer := wrapped[len(wrapped)-8:]
	if !bytes.Equal(footer, packer.BundleFooterMagic[:]) {
		t.Errorf("footer = %q, want %q", footer, packer.BundleFooterMagic[:])
	}
}

// TestExtractBundle_RejectsBadInputs covers the three failure modes
// surfaced by ExtractBundle: blob shorter than the 16-byte footer,
// missing magic, declared offset escaping the blob.
func TestExtractBundle_RejectsBadInputs(t *testing.T) {
	t.Run("tooShort", func(t *testing.T) {
		_, err := packer.ExtractBundle([]byte{0x01, 0x02})
		if !errors.Is(err, packer.ErrBundleTruncated) {
			t.Errorf("err = %v, want ErrBundleTruncated", err)
		}
	})
	t.Run("badMagic", func(t *testing.T) {
		bogus := bytes.Repeat([]byte{0x42}, 32)
		_, err := packer.ExtractBundle(bogus)
		if !errors.Is(err, packer.ErrBundleBadMagic) {
			t.Errorf("err = %v, want ErrBundleBadMagic", err)
		}
	})
	t.Run("offsetOutOfRange", func(t *testing.T) {
		// Build a wrapped blob with the magic intact but a bogus huge offset.
		blob := make([]byte, 32)
		// offset = 999 (way past end-of-footer-start = 16)
		binary.LittleEndian.PutUint64(blob[16:24], 999)
		copy(blob[24:32], packer.BundleFooterMagic[:])
		_, err := packer.ExtractBundle(blob)
		if !errors.Is(err, packer.ErrBundleOutOfRange) {
			t.Errorf("err = %v, want ErrBundleOutOfRange", err)
		}
	})
}

// TestPackBinaryBundle_PayloadKeysIndependent asserts that successive
// packs without an explicit CipherKey yield distinct ciphertexts even
// when the plaintexts are identical — confirming the per-payload key is
// freshly random each time.
func TestPackBinaryBundle_PayloadKeysIndependent(t *testing.T) {
	pl := []packer.BundlePayload{{Binary: bytes.Repeat([]byte{0x42}, 1024)}}
	a, err := packer.PackBinaryBundle(pl, packer.BundleOptions{})
	if err != nil {
		t.Fatalf("pack a: %v", err)
	}
	b, err := packer.PackBinaryBundle(pl, packer.BundleOptions{})
	if err != nil {
		t.Fatalf("pack b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("two packs produced identical bundles — key randomisation broken")
	}
}
