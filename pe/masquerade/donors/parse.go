package donors

import (
	"sync"

	"github.com/oioio-space/maldev/pe/cert"
)

// ParseBlob loads the bundled WIN_CERTIFICATE blob for `id` and
// decodes it via [cert.Certificate.Parse], surfacing the leaf
// signer's Subject / Issuer / Serial / validity window + the
// full chain. Convenience over [LoadBlob] + manual cert.Parse.
//
// Returns [ErrNoBlob] for unknown IDs (matches [LoadBlob]) and
// the same parse-side sentinels (cert.ErrCertificateTooSmall,
// cert.ErrCertificateNoSigners) that cert.Parse returns.
func ParseBlob(id string) (*cert.ParsedAuthenticode, error) {
	raw, err := LoadBlob(id)
	if err != nil {
		return nil, err
	}
	return (&cert.Certificate{Raw: raw}).Parse()
}

// ParseAll returns the parsed Authenticode metadata for every
// bundled blob, keyed by donor ID. Useful for operator UIs that
// pick a donor by signer subject ("I want the Microsoft signer
// of svchost") rather than by name.
//
// Computed once and cached — the bundled bytes never change at
// runtime. Entries that fail to parse are silently dropped (the
// blob isn't propagated for a reason: the operator who wants the
// raw bytes has [LoadBlob]).
func ParseAll() map[string]*cert.ParsedAuthenticode {
	return parseAll()
}

var parseAll = sync.OnceValue(func() map[string]*cert.ParsedAuthenticode {
	ids := AvailableBlobs()
	out := make(map[string]*cert.ParsedAuthenticode, len(ids))
	for _, id := range ids {
		p, err := ParseBlob(id)
		if err != nil {
			continue
		}
		out[id] = p
	}
	return out
})
