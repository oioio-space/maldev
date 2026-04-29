package masquerade

import (
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/png"
	"os"

	"github.com/oioio-space/maldev/evasion/stealthopen"
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
	VersionInfo *VersionInfo
	Certificate *cert.Certificate

	rs       *winres.ResourceSet
	manifest winres.AppManifest
	icons    []*winres.Icon
	modified bool // set when caller overrides fields via Build options
}

// IconCount returns the number of icon groups extracted from the PE.
func (res *Resources) IconCount() int {
	return len(res.icons)
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

	rs.WalkType(winres.RT_MANIFEST, func(resID winres.Identifier, langID uint16, data []byte) bool {
		if len(data) > 0 && res.Manifest == nil {
			res.Manifest = data
			if m, mErr := winres.AppManifestFromXML(data); mErr == nil {
				res.manifest = m
			}
		}
		return res.Manifest == nil
	})

	rs.WalkType(winres.RT_GROUP_ICON, func(resID winres.Identifier, langID uint16, _ []byte) bool {
		ico, iErr := rs.GetIconTranslation(resID, langID)
		if iErr == nil {
			res.icons = append(res.icons, ico)
		}
		return true
	})

	var viDone bool
	rs.WalkType(winres.RT_VERSION, func(_ winres.Identifier, _ uint16, data []byte) bool {
		if len(data) > 0 && !viDone {
			if vi, vErr := version.FromBytes(data); vErr == nil {
				viDone = true
				res.VersionInfo = extractVersionStrings(vi)
			}
		}
		return !viDone
	})

	if hasCert, _ := cert.Has(pePath); hasCert {
		if c, cErr := cert.Read(pePath); cErr == nil {
			res.Certificate = c
		}
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
// When no fields have been overridden, reuses the original resource set
// directly — only patching the manifest execution level. Equivalent to
// [Resources.GenerateSysoVia] with a nil Creator.
func (res *Resources) GenerateSyso(output string, arch Arch, level ExecLevel) error {
	return res.GenerateSysoVia(nil, output, arch, level)
}

// GenerateSysoVia routes the .syso write through the operator-supplied
// [stealthopen.Creator]. nil falls back to a [stealthopen.StandardCreator]
// (plain os.Create).
func (res *Resources) GenerateSysoVia(creator stealthopen.Creator, output string, arch Arch, level ExecLevel) error {
	var rs *winres.ResourceSet

	if res.modified || res.rs == nil {
		rs = res.rebuildResourceSet()
	} else {
		// Reuse the original resource set from Extract — avoids
		// re-encoding icons and version info through a lossy round-trip.
		rs = res.rs
	}

	m := res.manifest
	m.ExecutionLevel = level.toWinres()
	m.UIAccess = false
	rs.SetManifest(m)

	wc, err := stealthopen.UseCreator(creator).Create(output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer wc.Close()

	if err := rs.WriteObject(wc, arch.toWinres()); err != nil {
		return fmt.Errorf("write object: %w", err)
	}
	return nil
}

func (res *Resources) rebuildResourceSet() *winres.ResourceSet {
	rs := &winres.ResourceSet{}

	for i, ico := range res.icons {
		rs.SetIcon(winres.ID(uint16(i+1)), ico)
	}

	if res.VersionInfo != nil {
		vi := res.buildVersionInfo()
		rs.SetVersionInfo(*vi)
	}

	return rs
}

func (res *Resources) buildVersionInfo() *version.Info {
	vi := &version.Info{}
	vi.FileVersion = parseVersion(res.VersionInfo.FileVersion)
	vi.ProductVersion = parseVersion(res.VersionInfo.ProductVersion)
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

func parseVersion(s string) [4]uint16 {
	var v [4]uint16
	fmt.Sscanf(s, "%d.%d.%d.%d", &v[0], &v[1], &v[2], &v[3])
	return v
}

// ErrEmptySourcePE is returned when WithSourcePE is called with an empty path.
var ErrEmptySourcePE = errors.New("masquerade: source PE path cannot be empty")

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

// WithIcons overrides the icon resources using winres.Icon values
// (obtained from a previous Extract or from the winres library directly).
func WithIcons(icons []*winres.Icon) Option {
	return func(c *buildConfig) { c.icons = icons }
}

// WithIconFile loads an icon from a .png, .ico, or any image file
// supported by Go's image package and sets it as the application icon.
func WithIconFile(path string) Option {
	return func(c *buildConfig) {
		ico, err := IconFromFile(path)
		if err == nil {
			c.icons = []*winres.Icon{ico}
		}
	}
}

// WithIconImage creates an icon from a Go image.Image and sets it as
// the application icon.
func WithIconImage(img image.Image) Option {
	return func(c *buildConfig) {
		ico, err := IconFromImage(img)
		if err == nil {
			c.icons = []*winres.Icon{ico}
		}
	}
}

// IconFromFile loads an image file (PNG, ICO, BMP, JPEG, etc.) and
// converts it to an icon suitable for PE embedding. The winres library
// automatically generates all standard icon sizes (256, 128, 64, 48,
// 32, 16 px).
func IconFromFile(path string) (*winres.Icon, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open icon: %w", err)
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("decode icon: %w", err)
	}
	return IconFromImage(img)
}

// IconFromImage converts a Go image.Image to an icon suitable for PE
// embedding. All standard sizes are generated automatically.
func IconFromImage(img image.Image) (*winres.Icon, error) {
	ico, err := winres.NewIconFromResizedImage(img, nil)
	if err != nil {
		return nil, fmt.Errorf("create icon: %w", err)
	}
	return ico, nil
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

	if cfg.sourcePE == "" && hasSourcePEOption(opts) {
		return ErrEmptySourcePE
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
			manifest: winres.AppManifest{Compatibility: winres.Win10AndAbove},
		}
	}

	if cfg.versionInfo != nil {
		res.VersionInfo = cfg.versionInfo
		res.modified = true
	}
	if cfg.manifest != nil {
		res.Manifest = cfg.manifest
		if parsed, err := winres.AppManifestFromXML(cfg.manifest); err == nil {
			res.manifest = parsed
		}
		res.modified = true
	}
	if cfg.icons != nil {
		res.icons = cfg.icons
		res.modified = true
	}
	if cfg.certificate != nil {
		res.Certificate = cfg.certificate
	}

	return res.GenerateSyso(output, arch, cfg.execLevel)
}

// hasSourcePEOption checks whether WithSourcePE was explicitly called
// (distinguishes "not provided" from "provided with empty string").
func hasSourcePEOption(opts []Option) bool {
	cfg := &buildConfig{sourcePE: "\x00sentinel"}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg.sourcePE != "\x00sentinel"
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
