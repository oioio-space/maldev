package donors_test

import (
	"errors"
	"slices"
	"testing"

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
