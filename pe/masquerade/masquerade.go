package masquerade

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/cert"
	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

// ExecLevel represents the requested execution level in an application manifest.
type ExecLevel int

const (
	AsInvoker            ExecLevel = iota
	HighestAvailable
	RequireAdministrator
)

func (l ExecLevel) String() string {
	switch l {
	case AsInvoker:
		return "asInvoker"
	case HighestAvailable:
		return "highestAvailable"
	case RequireAdministrator:
		return "requireAdministrator"
	default:
		return fmt.Sprintf("ExecLevel(%d)", int(l))
	}
}

// toWinres converts to the winres library's execution level type.
func (l ExecLevel) toWinres() winres.ExecutionLevel {
	switch l {
	case HighestAvailable:
		return winres.HighestAvailable
	case RequireAdministrator:
		return winres.RequireAdministrator
	default:
		return winres.AsInvoker
	}
}

// Arch represents the target CPU architecture for .syso generation.
type Arch int

const (
	AMD64 Arch = iota
	I386
)

// toWinres converts to the winres library's architecture type.
func (a Arch) toWinres() winres.Arch {
	if a == I386 {
		return winres.ArchI386
	}
	return winres.ArchAMD64
}

// VersionInfo holds the standard version resource strings from a PE file.
type VersionInfo struct {
	FileDescription  string
	ProductName      string
	CompanyName      string
	OriginalFilename string
	InternalName     string
	FileVersion      string
	ProductVersion   string
	LegalCopyright   string
}

// Resources holds all extracted PE resources ready for modification and
// .syso generation.
type Resources struct {
	Manifest    []byte
	Icons       []*winres.Icon
	VersionInfo *VersionInfo
	Certificate *cert.Certificate

	rs       *winres.ResourceSet
	manifest winres.AppManifest
	rawVI    *version.Info
}

// Extract opens a PE file and extracts its manifest, icons, version info,
// and Authenticode certificate.
func Extract(pePath string) (*Resources, error) {
	f, err := os.Open(pePath)
	if err != nil {
		return nil, fmt.Errorf("open PE: %w", err)
	}
	defer f.Close()

	rs, err := winres.LoadFromEXE(f)
	if err != nil {
		return nil, fmt.Errorf("load resources: %w", err)
	}

	res := &Resources{rs: rs}

	// Manifest: take the first RT_MANIFEST entry regardless of language.
	rs.WalkType(winres.RT_MANIFEST, func(resID winres.Identifier, langID uint16, data []byte) bool {
		if len(data) > 0 && res.Manifest == nil {
			res.Manifest = data
			if m, mErr := winres.AppManifestFromXML(data); mErr == nil {
				res.manifest = m
			}
		}
		return res.Manifest == nil
	})

	// Icons: walk all RT_GROUP_ICON entries.
	rs.WalkType(winres.RT_GROUP_ICON, func(resID winres.Identifier, langID uint16, _ []byte) bool {
		ico, iErr := rs.GetIconTranslation(resID, langID)
		if iErr == nil {
			res.Icons = append(res.Icons, ico)
		}
		return true
	})

	// Version info: take the first RT_VERSION entry regardless of language.
	rs.WalkType(winres.RT_VERSION, func(_ winres.Identifier, _ uint16, data []byte) bool {
		if len(data) > 0 && res.rawVI == nil {
			if vi, vErr := version.FromBytes(data); vErr == nil {
				res.rawVI = vi
				res.VersionInfo = extractVersionStrings(vi)
			}
		}
		return res.rawVI == nil
	})

	// Certificate: optional, ignore ErrNoCertificate.
	if c, cErr := cert.Read(pePath); cErr == nil {
		res.Certificate = c
	} else if !errors.Is(cErr, cert.ErrNoCertificate) {
		return nil, fmt.Errorf("read certificate: %w", cErr)
	}

	return res, nil
}

// extractVersionStrings unmarshals version.Info via JSON to read the string
// table. The library exposes no getters — JSON is the only extraction path.
func extractVersionStrings(vi *version.Info) *VersionInfo {
	data, err := vi.MarshalJSON()
	if err != nil {
		return &VersionInfo{
			FileVersion:    fmtVersion(vi.FileVersion),
			ProductVersion: fmtVersion(vi.ProductVersion),
		}
	}

	var raw struct {
		Info map[string]map[string]string `json:"info"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return &VersionInfo{
			FileVersion:    fmtVersion(vi.FileVersion),
			ProductVersion: fmtVersion(vi.ProductVersion),
		}
	}

	// Take the first available translation.
	for _, strings := range raw.Info {
		return &VersionInfo{
			FileDescription:  strings[version.FileDescription],
			ProductName:      strings[version.ProductName],
			CompanyName:      strings[version.CompanyName],
			OriginalFilename: strings[version.OriginalFilename],
			InternalName:     strings[version.InternalName],
			FileVersion:      strings[version.FileVersion],
			ProductVersion:   strings[version.ProductVersion],
			LegalCopyright:   strings[version.LegalCopyright],
		}
	}

	return &VersionInfo{
		FileVersion:    fmtVersion(vi.FileVersion),
		ProductVersion: fmtVersion(vi.ProductVersion),
	}
}

// fmtVersion formats a 4-part version array as "major.minor.patch.build".
func fmtVersion(v [4]uint16) string {
	return fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3])
}
