//go:build windows

package folder

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestGetKnown_KnownIDsResolve calls GetKnown against a sample of
// `windows.FOLDERID_*` GUIDs with KF_FLAG_DONT_VERIFY so the path
// is returned without an existence check (decouples the test
// from host-specific fs state — `FOLDERID_CommonStartup` may or
// may not be present depending on the build).
func TestGetKnown_KnownIDsResolve(t *testing.T) {
	cases := []struct {
		name string
		id   *windows.KNOWNFOLDERID
	}{
		{"Profile", windows.FOLDERID_Profile},
		{"Desktop", windows.FOLDERID_Desktop},
		{"Documents", windows.FOLDERID_Documents},
		{"Downloads", windows.FOLDERID_Downloads},
		{"LocalAppData", windows.FOLDERID_LocalAppData},
		{"RoamingAppData", windows.FOLDERID_RoamingAppData},
		{"Programs", windows.FOLDERID_Programs},
		{"Startup", windows.FOLDERID_Startup},
		{"System", windows.FOLDERID_System},
		{"Windows", windows.FOLDERID_Windows},
		{"ProgramFiles", windows.FOLDERID_ProgramFiles},
		{"ProgramFilesX86", windows.FOLDERID_ProgramFilesX86},
		{"PublicDesktop", windows.FOLDERID_PublicDesktop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, err := GetKnown(tc.id, windows.KF_FLAG_DONT_VERIFY)
			if err != nil {
				t.Fatalf("GetKnown(%s) err = %v, want nil", tc.name, err)
			}
			if path == "" {
				t.Fatalf("GetKnown(%s) returned empty path", tc.name)
			}
			if len(path) < 2 || path[1] != ':' {
				t.Errorf("GetKnown(%s) = %q, want drive-letter prefix", tc.name, path)
			}
		})
	}
}

// TestGetKnown_KFCreate confirms KF_FLAG_CREATE returns a path
// even when the underlying directory might not pre-exist. We use
// Documents as the smoke target — present on any healthy host.
func TestGetKnown_KFCreate(t *testing.T) {
	path, err := GetKnown(windows.FOLDERID_Documents, windows.KF_FLAG_CREATE)
	if err != nil {
		t.Fatalf("GetKnown(Documents, KF_FLAG_CREATE) err = %v", err)
	}
	if !strings.Contains(strings.ToLower(path), "documents") {
		t.Errorf("expected path containing 'documents', got %q", path)
	}
}

// TestGetKnown_UnknownGUID_ReturnsErrKnownFolderNotFound passes a
// random GUID no Shell extension has registered. SHGetKnownFolderPath
// returns E_INVALIDARG (HRESULT 0x80070057); GetKnown wraps it as
// ErrKnownFolderNotFound.
func TestGetKnown_UnknownGUID_ReturnsErrKnownFolderNotFound(t *testing.T) {
	bogus, err := windows.GUIDFromString("{DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}")
	if err != nil {
		t.Fatalf("guid parse: %v", err)
	}
	bogusKF := windows.KNOWNFOLDERID(bogus)
	path, err := GetKnown(&bogusKF, 0)
	if !errors.Is(err, ErrKnownFolderNotFound) {
		t.Fatalf("GetKnown(bogus) err = %v, want ErrKnownFolderNotFound", err)
	}
	if path != "" {
		t.Errorf("GetKnown(bogus) path = %q, want empty", path)
	}
}
