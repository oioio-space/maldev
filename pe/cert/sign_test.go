package cert_test

import (
	"crypto/x509/pkix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/oioio-space/maldev/pe/cert"
)

// signablePEFixture copies a small System32 PE to TempDir so the
// test can mutate it freely. Skips on non-Windows or when no
// suitable donor is available.
func signablePEFixture(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("requires a Windows-host PE to sign")
	}
	candidates := []string{
		`C:\Windows\System32\notepad.exe`,
		`C:\Windows\System32\calc.exe`,
		`C:\Windows\System32\xcopy.exe`,
	}
	for _, src := range candidates {
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(t.TempDir(), filepath.Base(src))
		if err := copyFile(src, dst); err != nil {
			continue
		}
		return dst
	}
	t.Skip("no signable PE fixture available")
	return ""
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func TestSignPE_ProducesParseableSignedDataWithRightOID(t *testing.T) {
	pePath := signablePEFixture(t)

	chain, err := cert.SignPE(pePath, cert.SignOptions{
		LeafSubject: pkix.Name{
			CommonName:   "maldev test signer",
			Organization: []string{"maldev"},
		},
		RootSubject: pkix.Name{
			CommonName: "maldev test root CA",
		},
	})
	if err != nil {
		t.Fatalf("SignPE: %v", err)
	}
	if chain.Leaf == nil || chain.Root == nil {
		t.Fatal("SignPE returned chain with nil Leaf or Root")
	}

	// Round-trip via cert.Read + Parse — exercises the secDre4mer/pkcs7
	// parser against our hand-rolled SignedData. If our DER is broken
	// at the top level this fails immediately.
	c, err := cert.Read(pePath)
	if err != nil {
		t.Fatalf("Read after SignPE: %v", err)
	}
	parsed, err := c.Parse()
	if err != nil {
		t.Fatalf("Parse after SignPE: %v", err)
	}
	if parsed.Signer == nil {
		t.Fatal("parsed.Signer is nil — SignerInfo missing")
	}
	if want := "maldev test signer"; !strings.Contains(parsed.Subject, want) {
		t.Errorf("Subject = %q, want it to contain %q", parsed.Subject, want)
	}
	if got := len(parsed.Certs); got < 2 {
		t.Errorf("chain has %d certs, want ≥ 2 (leaf + root)", got)
	}

	t.Logf("signed PE at: %s", pePath)
	t.Logf("manual verify: signtool verify /pa /v %q", pePath)
	t.Logf("(self-signed root → expect 'untrusted root', but structure must parse)")
}

// TestSignPE_AgainstSigntool runs the actual `signtool verify /pa`
// against the SignPE output. Gated on SIGNTOOL_VERIFY=1 because
// signtool.exe is part of the Windows SDK (not always installed).
//
// Expected output: "SignTool Error: A certificate chain processed,
// but terminated in a root certificate which is not trusted by the
// trust provider." That error confirms structural parsing succeeded
// — only the trust-store walk fails (intentional: self-signed root).
func TestSignPE_AgainstSigntool(t *testing.T) {
	if os.Getenv("SIGNTOOL_VERIFY") != "1" {
		t.Skip("set SIGNTOOL_VERIFY=1 + signtool.exe in PATH (or Windows SDK) to enable")
	}
	pePath := signablePEFixture(t)

	if _, err := cert.SignPE(pePath, cert.SignOptions{
		LeafSubject: pkix.Name{CommonName: "maldev test signer"},
		RootSubject: pkix.Name{CommonName: "maldev test root CA"},
	}); err != nil {
		t.Fatalf("SignPE: %v", err)
	}

	signtool := os.Getenv("SIGNTOOL_PATH")
	if signtool == "" {
		signtool = `C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe`
	}
	cmd := exec.Command(signtool, "verify", "/pa", "/v", pePath)
	out, err := cmd.CombinedOutput()
	t.Logf("signtool output:\n%s", out)

	lower := strings.ToLower(string(out))

	// Hard requirements — signtool MUST extract the chain. If it
	// can't, our DER is structurally broken (wrong tag, wrong
	// nesting, missing field). Those substrings appear ONLY when
	// the SignedData parses cleanly and the chain walk reaches
	// our forged certs.
	for _, want := range []string{"signing certificate chain", "maldev test signer", "maldev test root ca"} {
		if !strings.Contains(lower, want) {
			t.Errorf("signtool output missing %q — DER structure likely broken", want)
		}
	}

	// Two acceptable outcomes for the trust-store verdict:
	//   (1) success — chain trusted (won't happen for self-signed)
	//   (2) "untrusted root" error — structure parsed cleanly, only
	//       trust store walk failed (the expected case)
	if err == nil {
		return // (1)
	}
	if strings.Contains(lower, "untrusted") || strings.Contains(lower, "not trusted") || strings.Contains(lower, "0x800b0109") {
		return // (2) — known/expected
	}
	t.Errorf("signtool returned an unexpected error (not 'untrusted root'): %v", err)
}
