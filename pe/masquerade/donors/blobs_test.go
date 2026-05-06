package donors_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/masquerade/donors"
)

func TestLoadBlob_KnownIDReturnsWinCertificateBytes(t *testing.T) {
	for _, id := range donors.AvailableBlobs() {
		t.Run(id, func(t *testing.T) {
			data, err := donors.LoadBlob(id)
			if err != nil {
				t.Fatalf("LoadBlob(%q): %v", id, err)
			}
			// WIN_CERTIFICATE: 8-byte header + at least a few bytes
			// of PKCS#7 SignedData. Real Authenticode blobs run
			// 1500 bytes minimum.
			if len(data) < 256 {
				t.Errorf("blob %s too small (%d bytes) — likely truncated",
					id, len(data))
			}
		})
	}
}

func TestLoadBlob_UnknownIDReturnsErrNoBlob(t *testing.T) {
	_, err := donors.LoadBlob("does-not-exist-xyz")
	if !errors.Is(err, donors.ErrNoBlob) {
		t.Fatalf("LoadBlob(unknown): got %v, want ErrNoBlob", err)
	}
}

func TestAvailableBlobs_ListsAtLeastOneIdentity(t *testing.T) {
	got := donors.AvailableBlobs()
	if len(got) == 0 {
		t.Fatal("AvailableBlobs returned empty — no blobs bundled?")
	}
	// Every ID returned should round-trip through LoadBlob.
	for _, id := range got {
		if _, err := donors.LoadBlob(id); err != nil {
			t.Errorf("AvailableBlobs reported %q but LoadBlob failed: %v", id, err)
		}
	}
}

func TestAvailableBlobs_AllIDsAreInDonorList(t *testing.T) {
	knownIDs := make([]string, 0, len(donors.All))
	for _, d := range donors.All {
		knownIDs = append(knownIDs, d.ID)
	}
	for _, id := range donors.AvailableBlobs() {
		if !slices.Contains(knownIDs, id) {
			t.Errorf("bundled blob %q has no entry in donors.All", id)
		}
	}
}

func TestParseBlob_KnownIDExposesSignerSubject(t *testing.T) {
	for _, id := range donors.AvailableBlobs() {
		t.Run(id, func(t *testing.T) {
			p, err := donors.ParseBlob(id)
			if err != nil {
				t.Fatalf("ParseBlob(%q): %v", id, err)
			}
			if p.Signer == nil {
				t.Fatalf("%s: nil Signer", id)
			}
			if p.Subject == "" {
				t.Errorf("%s: empty Subject", id)
			}
			if p.NotAfter.IsZero() {
				t.Errorf("%s: zero NotAfter", id)
			}
			// Sanity guard against blobs whose validity window
			// already closed years ago (would surface in operator
			// UIs as "expired publisher" hints).
			if p.NotAfter.Before(time.Now().AddDate(-5, 0, 0)) {
				t.Errorf("%s: NotAfter %v is more than 5 years stale — refresh donors/blobs/", id, p.NotAfter)
			}
		})
	}
}

func TestParseBlob_UnknownIDReturnsErrNoBlob(t *testing.T) {
	_, err := donors.ParseBlob("does-not-exist-xyz")
	if !errors.Is(err, donors.ErrNoBlob) {
		t.Fatalf("ParseBlob(unknown): got %v, want ErrNoBlob", err)
	}
}

func TestParseAll_CoversEveryBundledBlob(t *testing.T) {
	parsed := donors.ParseAll()
	for _, id := range donors.AvailableBlobs() {
		if _, ok := parsed[id]; !ok {
			t.Errorf("ParseAll missing entry for bundled blob %q", id)
		}
	}
}
