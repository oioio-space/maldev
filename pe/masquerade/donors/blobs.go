package donors

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
)

// Bundled cert blob snapshot taken 2026-05-06 from a Windows 11
// Pro 26200 dev box with the donors installed at default paths.
// Each `<id>.bin` is the raw WIN_CERTIFICATE structure (header
// + PKCS#7 SignedData) ready to feed cert.Write.
//
// Re-extract any time with:
//
//	go run ./cmd/cert-snapshot -out ./pe/masquerade/donors/blobs
//
// Operators with custom donors should commit replacements over
// the bundled defaults — Authenticode certs rotate (Microsoft
// renewed roots in 2024, Adobe in 2023) and stale blobs may
// trip "expired publisher" UI hints.
//
//go:embed blobs/*.bin
var blobsFS embed.FS

// SnapshotDate is the YYYY-MM-DD the bundled blobs were taken.
// Operators eyeball this against their threat-model freshness
// budget — anything older than ~12 months on a high-rotation
// vendor (Microsoft, Adobe) likely needs a re-extract.
const SnapshotDate = "2026-05-06"

// ErrNoBlob is returned by [LoadBlob] / [Apply] when the
// requested donor ID has no bundled cert. Common reasons:
// the donor signs via system catalog (cmd, notepad), ships
// unsigned (sevenzip), or the source host couldn't extract
// (wt under WindowsApps DACL).
var ErrNoBlob = errors.New("donors: no bundled cert blob for that ID")

// LoadBlob returns the raw WIN_CERTIFICATE bytes bundled for
// the given donor ID. Returns [ErrNoBlob] for IDs without a
// bundled blob (run cmd/cert-snapshot to refresh and add).
//
// The returned slice is a copy — callers can mutate freely.
func LoadBlob(id string) ([]byte, error) {
	data, err := blobsFS.ReadFile("blobs/" + id + ".bin")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNoBlob, id)
	}
	if err != nil {
		return nil, fmt.Errorf("read bundled blob %s: %w", id, err)
	}
	return data, nil
}

// AvailableBlobs lists every donor ID that has a bundled blob
// inside the package — i.e. every successful entry produced by
// the last cmd/cert-snapshot run committed to the repo.
//
// Useful for operator UIs ("which donors can I graft offline?")
// and for tests that want to round-trip every bundled blob.
func AvailableBlobs() []string {
	entries, err := blobsFS.ReadDir("blobs")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if len(name) > 4 && name[len(name)-4:] == ".bin" {
			out = append(out, name[:len(name)-4])
		}
	}
	return out
}
