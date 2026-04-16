package masquerade

import (
	"image"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/oioio-space/maldev/pe/cert"
	"github.com/stretchr/testify/require"
)

func testPEPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("need Windows PE for extraction test")
	}
	p := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("notepad.exe not found: %v", err)
	}
	return p
}

func TestExtract(t *testing.T) {
	pe := testPEPath(t)
	res, err := Extract(pe)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.Manifest)
	require.NotNil(t, res.VersionInfo)
	require.Greater(t, res.IconCount(), 0, "expected icons")
}

func TestExtractVersionInfo(t *testing.T) {
	pe := testPEPath(t)
	res, err := Extract(pe)
	require.NoError(t, err)
	require.NotEmpty(t, res.VersionInfo.FileDescription)
	require.NotEmpty(t, res.VersionInfo.CompanyName)
	t.Logf("FileDescription: %s", res.VersionInfo.FileDescription)
	t.Logf("CompanyName: %s", res.VersionInfo.CompanyName)
}

func TestExtractNonExistent(t *testing.T) {
	_, err := Extract(`C:\nonexistent_pe_12345.exe`)
	require.Error(t, err)
}

func TestExecLevelString(t *testing.T) {
	require.Equal(t, "asInvoker", AsInvoker.String())
	require.Equal(t, "highestAvailable", HighestAvailable.String())
	require.Equal(t, "requireAdministrator", RequireAdministrator.String())
}

func TestGenerateSyso(t *testing.T) {
	pe := testPEPath(t)
	res, err := Extract(pe)
	require.NoError(t, err)

	out := filepath.Join(t.TempDir(), "resource_windows_amd64.syso")
	err = res.GenerateSyso(out, AMD64, AsInvoker)
	require.NoError(t, err)

	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))
}

func TestGenerateSysoRequireAdmin(t *testing.T) {
	pe := testPEPath(t)
	res, err := Extract(pe)
	require.NoError(t, err)

	out := filepath.Join(t.TempDir(), "resource_windows_amd64.syso")
	err = res.GenerateSyso(out, AMD64, RequireAdministrator)
	require.NoError(t, err)

	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))
}

func TestClone(t *testing.T) {
	pe := testPEPath(t)
	out := filepath.Join(t.TempDir(), "resource_windows_amd64.syso")
	err := Clone(pe, out, AMD64, AsInvoker)
	require.NoError(t, err)

	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))
}

func TestBuildCustom(t *testing.T) {
	out := filepath.Join(t.TempDir(), "resource_windows_amd64.syso")
	err := Build(out, AMD64,
		WithExecLevel(RequireAdministrator),
		WithVersionInfo(&VersionInfo{
			FileDescription:  "Windows Service Host",
			CompanyName:      "Microsoft Corporation",
			ProductName:      "Microsoft Windows",
			OriginalFilename: "svchost.exe",
			FileVersion:      "10.0.19041.1",
			ProductVersion:   "10.0.19041.1",
		}),
	)
	require.NoError(t, err)

	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))
}

func TestBuildFromSource(t *testing.T) {
	pe := testPEPath(t)
	out := filepath.Join(t.TempDir(), "resource_windows_amd64.syso")
	err := Build(out, AMD64,
		WithSourcePE(pe),
		WithExecLevel(HighestAvailable),
	)
	require.NoError(t, err)

	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))
}

func TestBuildWithCertificate(t *testing.T) {
	pe := testPEPath(t)

	c, err := cert.Read(pe)
	if err != nil {
		t.Skip("notepad.exe has no certificate on this system")
	}

	out := filepath.Join(t.TempDir(), "resource_windows_amd64.syso")
	err = Build(out, AMD64,
		WithSourcePE(pe),
		WithCertificate(c),
	)
	require.NoError(t, err)
}

func TestIconFromImage(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	ico, err := IconFromImage(img)
	require.NoError(t, err)
	require.NotNil(t, ico)
}

func TestIconFromFile(t *testing.T) {
	// Create a minimal PNG in a temp file.
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "icon.png")
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	f, err := os.Create(pngPath)
	require.NoError(t, err)
	require.NoError(t, png.Encode(f, img))
	f.Close()

	ico, err := IconFromFile(pngPath)
	require.NoError(t, err)
	require.NotNil(t, ico)
}

func TestIconFromFileNotFound(t *testing.T) {
	_, err := IconFromFile(`C:\nonexistent_icon_12345.png`)
	require.Error(t, err)
}

func TestWithIconFile(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "icon.png")
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	f, err := os.Create(pngPath)
	require.NoError(t, err)
	require.NoError(t, png.Encode(f, img))
	f.Close()

	out := filepath.Join(dir, "resource.syso")
	err = Build(out, AMD64,
		WithIconFile(pngPath),
		WithVersionInfo(&VersionInfo{
			FileDescription: "Test App",
			FileVersion:     "1.0.0.0",
			ProductVersion:  "1.0.0.0",
		}),
	)
	require.NoError(t, err)

	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))
}

func TestWithIconImage(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	out := filepath.Join(t.TempDir(), "resource.syso")
	err := Build(out, AMD64,
		WithIconImage(img),
		WithVersionInfo(&VersionInfo{
			FileDescription: "Test App",
			FileVersion:     "1.0.0.0",
			ProductVersion:  "1.0.0.0",
		}),
	)
	require.NoError(t, err)

	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))
}

func TestBuildEmptySourcePE(t *testing.T) {
	out := filepath.Join(t.TempDir(), "resource.syso")
	err := Build(out, AMD64, WithSourcePE(""))
	require.ErrorIs(t, err, ErrEmptySourcePE)
}

func TestModifyVersionBeforeSyso(t *testing.T) {
	pe := testPEPath(t)
	res, err := Extract(pe)
	require.NoError(t, err)

	res.VersionInfo.OriginalFilename = "custom.exe"
	res.VersionInfo.FileDescription = "Custom App"

	out := filepath.Join(t.TempDir(), "resource_windows_amd64.syso")
	err = res.GenerateSyso(out, AMD64, AsInvoker)
	require.NoError(t, err)

	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))
}
