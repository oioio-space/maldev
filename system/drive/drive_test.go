//go:build windows

package drive

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetLogicalDriveType(t *testing.T) {
	dt, err := GetLogicalDriveType("C:\\")
	require.NoError(t, err)
	assert.Equal(t, FIXED, dt)
}

func TestDriveTypeString(t *testing.T) {
	assert.Equal(t, "fixed", FIXED.String())
	assert.Equal(t, "unknown", UNKNOWN.String())
	assert.Equal(t, "removable", REMOVABLE.String())
	assert.Equal(t, "cdrom", CDROM.String())
	assert.Equal(t, "remote", REMOTE.String())
	assert.Equal(t, "ramdisk", RAMDISK.String())
	assert.Equal(t, "noRootDir", NOROOTDIR.String())
}

func TestGetVolumeInformation(t *testing.T) {
	info, err := GetVolumeInformation("C:\\")
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
	assert.Equal(t, FIXED, d.Type)
	assert.NotNil(t, d.Infos)
}
