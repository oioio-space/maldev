package cert

import (
	"crypto"
	"fmt"

	"github.com/oioio-space/maldev/pe/parse"
)

// AuthenticodeContent reads the PE at pePath, computes its
// SHA-256 Authenticode hash (saferwall's [parse.File.Authentihash]),
// and returns the canonical [SpcIndirectDataContent] DER bytes —
// the payload that goes into the [SignedData.encapContentInfo.eContent]
// slot of a real Authenticode signature.
//
// Use it to prepare the input to an external signer (signtool /sign,
// osslsigncode) when the signing key lives outside the build host:
//
//	content, _ := cert.AuthenticodeContent("implant.exe")
//	// pipe `content` to a signing service, get back the PKCS#7
//	// SignedData blob, then cert.Write it back.
//
// SHA-256 is the modern Authenticode default and the only digest
// saferwall surfaces directly; for SHA-1 legacy support, hash the
// PE manually and call [BuildSpcIndirectDataContent].
//
// Phase 1 of the path to real Authenticode. The Phase 2 hand-rolled
// SignedData wrapping (eContentType = OIDSpcIndirectDataContent +
// signed attributes + leaf-key signature) lives in [SignPE].
func AuthenticodeContent(pePath string) ([]byte, error) {
	pf, err := parse.Open(pePath)
	if err != nil {
		return nil, fmt.Errorf("AuthenticodeContent: open %s: %w", pePath, err)
	}
	defer pf.Close()
	digest := pf.Authentihash()
	if len(digest) == 0 {
		return nil, fmt.Errorf("AuthenticodeContent: empty Authentihash for %s", pePath)
	}
	return BuildSpcIndirectDataContent(digest, crypto.SHA256)
}
