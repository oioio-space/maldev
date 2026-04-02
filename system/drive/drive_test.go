//go:build windows

package drive

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestType(t *testing.T) {
	dt, err := Type("C:\\")
	require.NoError(t, err)
	assert.Equal(t, Fixed, dt)
}

func TestDriveTypeString(t *testing.T) {
	assert.Equal(t, "fixed", Fixed.String())
	assert.Equal(t, "unknown", Unknown.String())
	assert.Equal(t, "removable", Removable.String())
	assert.Equal(t, "cdrom", CDROM.String())
	assert.Equal(t, "remote", Remote.String())
	assert.Equal(t, "ramdisk", RAMDisk.String())
	assert.Equal(t, "noRootDir", NoRootDir.String())
}

func TestVolume(t *testing.T) {
	info, err := Volume("C:\\")
	require.NoError(t, err)
	require.NotNil(t, info)
	// NTFS is the dominant Windows filesystem; confirm it is populated.
	assert.NotEmpty(t, info.FileSystemName)
}

func TestNewDrive(t *testing.T) {
	d, err := NewDrive("C:\\")
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.Equal(t, "C:\\", d.Letter)
	assert.Equal(t, Fixed, d.Type)
	assert.NotNil(t, d.Infos)
}
