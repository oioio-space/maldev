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

// GenerateSyso builds a .syso COFF object from the extracted resources.
func (res *Resources) GenerateSyso(output string, arch Arch, level ExecLevel) error {
	rs := &winres.ResourceSet{}

	for i, ico := range res.Icons {
		if err := rs.SetIcon(winres.ID(uint16(i+1)), ico); err != nil {
			return fmt.Errorf("set icon %d: %w", i, err)
		}
	}

	if res.VersionInfo != nil {
		vi := res.buildVersionInfo()
		rs.SetVersionInfo(*vi)
	}

	m := res.manifest
	m.ExecutionLevel = level.toWinres()
	m.UIAccess = false
	rs.SetManifest(m)

	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer f.Close()

	if err := rs.WriteObject(f, arch.toWinres()); err != nil {
		return fmt.Errorf("write object: %w", err)
	}
	return nil
}

func (res *Resources) buildVersionInfo() *version.Info {
	vi := &version.Info{}
	if res.rawVI != nil {
		vi.FileVersion = res.rawVI.FileVersion
		vi.ProductVersion = res.rawVI.ProductVersion
	}
	vi.Set(0, version.FileDescription, res.VersionInfo.FileDescription)
	vi.Set(0, version.ProductName, res.VersionInfo.ProductName)
	vi.Set(0, version.CompanyName, res.VersionInfo.CompanyName)
	vi.Set(0, version.OriginalFilename, res.VersionInfo.OriginalFilename)
	vi.Set(0, version.InternalName, res.VersionInfo.InternalName)
	vi.Set(0, version.FileVersion, res.VersionInfo.FileVersion)
	vi.Set(0, version.ProductVersion, res.VersionInfo.ProductVersion)
	vi.Set(0, version.LegalCopyright, res.VersionInfo.LegalCopyright)
	return vi
}

// Option configures a Build call.
type Option func(*buildConfig)

type buildConfig struct {
	sourcePE    string
	execLevel   ExecLevel
	manifest    []byte
	versionInfo *VersionInfo
	icons       []*winres.Icon
	certificate *cert.Certificate
}

// WithSourcePE extracts resources from an existing PE as a starting point.
func WithSourcePE(pePath string) Option {
	return func(c *buildConfig) { c.sourcePE = pePath }
}

// WithExecLevel sets the requested execution level in the manifest.
func WithExecLevel(level ExecLevel) Option {
	return func(c *buildConfig) { c.execLevel = level }
}

// WithManifest overrides the manifest with raw XML.
func WithManifest(xml []byte) Option {
	return func(c *buildConfig) { c.manifest = xml }
}

// WithVersionInfo overrides the version resource strings.
func WithVersionInfo(vi *VersionInfo) Option {
	return func(c *buildConfig) { c.versionInfo = vi }
}

// WithIcons overrides the icon resources.
func WithIcons(icons []*winres.Icon) Option {
	return func(c *buildConfig) { c.icons = icons }
}

// WithCertificate stores a certificate for post-build application.
// The cert is NOT embedded in the .syso — it must be applied after go build
// via cert.Write on the final executable.
func WithCertificate(c *cert.Certificate) Option {
	return func(cfg *buildConfig) { cfg.certificate = c }
}

// Build generates a .syso COFF object from options, optionally starting from
// an existing PE. Without WithSourcePE, resources are created from scratch.
func Build(output string, arch Arch, opts ...Option) error {
	cfg := &buildConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	var res *Resources

	if cfg.sourcePE != "" {
		var err error
		res, err = Extract(cfg.sourcePE)
		if err != nil {
			return fmt.Errorf("extract source PE: %w", err)
		}
	} else {
		res = &Resources{
			rs:       &winres.ResourceSet{},
			manifest: winres.AppManifest{Compatibility: winres.Win10AndAbove},
		}
	}

	if cfg.versionInfo != nil {
		res.VersionInfo = cfg.versionInfo
	}
	if cfg.manifest != nil {
		res.Manifest = cfg.manifest
		if parsed, err := winres.AppManifestFromXML(cfg.manifest); err == nil {
			res.manifest = parsed
		}
	}
	if cfg.icons != nil {
		res.Icons = cfg.icons
	}
	if cfg.certificate != nil {
		res.Certificate = cfg.certificate
	}

	return res.GenerateSyso(output, arch, cfg.execLevel)
}

// Clone extracts resources from srcPE and generates a .syso in one step.
func Clone(srcPE, outputSyso string, arch Arch, level ExecLevel) error {
	res, err := Extract(srcPE)
	if err != nil {
		return err
	}
	return res.GenerateSyso(outputSyso, arch, level)
}

// fmtVersion formats a 4-part version array as "major.minor.patch.build".
func fmtVersion(v [4]uint16) string {
	return fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3])
}
