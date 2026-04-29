//go:build windows

package folder

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestGetKnown_KnownIDsResolve calls GetKnown against every shipped
// FOLDERID_* GUID with KFF_DONT_VERIFY so the path is returned
// without an existence check. This decouples the test from
// host-specific fs state (CommonStartup may or may not be present
// depending on the build).
func TestGetKnown_KnownIDsResolve(t *testing.T) {
	cases := []struct {
		name string
		id   windows.GUID
	}{
		{"Profile", FOLDERID_Profile},
		{"Desktop", FOLDERID_Desktop},
		{"Documents", FOLDERID_Documents},
		{"Downloads", FOLDERID_Downloads},
		{"LocalAppData", FOLDERID_LocalAppData},
		{"RoamingAppData", FOLDERID_RoamingAppData},
		{"Programs", FOLDERID_Programs},
		{"Startup", FOLDERID_Startup},
		{"System", FOLDERID_System},
		{"Windows", FOLDERID_Windows},
		{"ProgramFiles", FOLDERID_ProgramFiles},
		{"ProgramFilesX86", FOLDERID_ProgramFilesX86},
		{"PublicDesktop", FOLDERID_PublicDesktop},
		// FOLDERID_CommonStartup intentionally excluded from the
		// auto-resolve smoke test: its GUID is exported (callers
		// who want it can call GetKnown directly) but on some
		// host configurations / session types Shell32 returns
		// 0x80070002 (path not configured for the calling
		// principal).
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, err := GetKnown(tc.id, KFF_DONT_VERIFY)
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

// TestGetKnown_KFFCreate confirms KFF_CREATE returns a path even when
// the underlying directory might not pre-exist. We use Documents as
// the smoke target — it's always present on a healthy host either way.
func TestGetKnown_KFFCreate(t *testing.T) {
	path, err := GetKnown(FOLDERID_Documents, KFF_CREATE)
	if err != nil {
		t.Fatalf("GetKnown(Documents, KFF_CREATE) err = %v", err)
	}
	if !strings.Contains(strings.ToLower(path), "documents") {
		t.Errorf("expected path containing 'documents', got %q", path)
	}
}

// TestGetKnown_UnknownGUID_ReturnsErrKnownFolderNotFound passes a
// random GUID that no Shell extension has registered. SHGetKnownFolderPath
// returns E_INVALIDARG (HRESULT 0x80070057) which the wrapper translates
// to ErrKnownFolderNotFound.
func TestGetKnown_UnknownGUID_ReturnsErrKnownFolderNotFound(t *testing.T) {
	bogus, err := windows.GUIDFromString("{DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}")
	if err != nil {
		t.Fatalf("guid parse: %v", err)
	}
	path, err := GetKnown(bogus, 0)
	if !errors.Is(err, ErrKnownFolderNotFound) {
		t.Fatalf("GetKnown(bogus) err = %v, want ErrKnownFolderNotFound", err)
	}
	if path != "" {
		t.Errorf("GetKnown(bogus) path = %q, want empty", path)
	}
}
