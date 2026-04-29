//go:build windows

package drive

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeOf(t *testing.T) {
	dt := TypeOf("C:\\")
	assert.Equal(t, TypeFixed, dt)
}

func TestTypeOf_Invalid(t *testing.T) {
	dt := TypeOf("Z:\\nonexistent\\")
	assert.True(t, dt == TypeUnknown || dt == TypeNoRootDir,
		"expected TypeUnknown or TypeNoRootDir, got %s", dt)
}

func TestTypeString(t *testing.T) {
	tests := []struct {
		t    Type
		want string
	}{
		{TypeUnknown, "DRIVE_UNKNOWN"},
		{TypeNoRootDir, "DRIVE_NO_ROOT_DIR"},
		{TypeRemovable, "DRIVE_REMOVABLE"},
		{TypeFixed, "DRIVE_FIXED"},
		{TypeRemote, "DRIVE_REMOTE"},
		{TypeCDROM, "DRIVE_CDROM"},
		{TypeRAMDisk, "DRIVE_RAMDISK"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.t.String())
	}
}

func TestTypeString_OutOfRange(t *testing.T) {
	s := Type(99).String()
	assert.Contains(t, s, "99")
}

func TestVolumeOf(t *testing.T) {
	info, err := VolumeOf("C:\\")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.NotEmpty(t, info.FileSystemName)
	assert.Greater(t, info.SerialNumber, uint32(0))
}

func TestVolumeOf_InvalidDrive(t *testing.T) {
	_, err := VolumeOf("Z:\\nonexistent\\")
	assert.Error(t, err)
}

func TestNew(t *testing.T) {
	d, err := New("C:\\")
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.Equal(t, "C:\\", d.Letter)
	assert.Equal(t, TypeFixed, d.Type)
	assert.NotNil(t, d.Volume)
	assert.NotEmpty(t, d.Volume.FileSystemName)

	assert.NotEmpty(t, d.GUID, "should have a volume GUID")
	assert.Contains(t, d.GUID, "\\\\?\\Volume{")

	assert.NotEmpty(t, d.DevicePath, "should have a device path")
	assert.Contains(t, d.DevicePath, "\\Device\\")
}

func TestInfoKey(t *testing.T) {
	d, err := New("C:\\")
	require.NoError(t, err)
	// key should prefer GUID
	assert.Equal(t, d.GUID, d.key())

	// With empty GUID, falls back to letter
	d2 := &Info{Letter: "X:\\"}
	assert.Equal(t, "X:\\", d2.key())
}

func TestLogicalDriveLetters(t *testing.T) {
	letters, err := LogicalDriveLetters()
	require.NoError(t, err)
	assert.NotEmpty(t, letters)

	found := false
	for _, l := range letters {
		if l == "C:\\" {
			found = true
		}
		assert.Len(t, l, 3)
		assert.Equal(t, ":\\", l[1:])
	}
	assert.True(t, found, "C:\\ should be in the drive list")
}

func TestEventKindString(t *testing.T) {
	assert.Equal(t, "added", EventAdded.String())
	assert.Equal(t, "removed", EventRemoved.String())
}

func TestWatcher_Snapshot(t *testing.T) {
	ctx := context.Background()
	w := NewWatcher(ctx, func(d *Info) bool { return d.Type == TypeFixed })

	drives, err := w.Snapshot()
	require.NoError(t, err)
	assert.NotEmpty(t, drives, "should find at least one fixed drive")

	for _, d := range drives {
		assert.Equal(t, TypeFixed, d.Type)
	}
}

func TestWatcher_Watch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	w := NewWatcher(ctx, func(*Info) bool { return true })
	ch, err := w.Watch(100 * time.Millisecond)
	require.NoError(t, err)

	// No new drives expected — channel should close when context cancels.
	for ev := range ch {
		if ev.Err != nil {
			t.Logf("watcher error: %v", ev.Err)
		}
		if ev.Drive != nil {
			t.Logf("watcher %s: %s", ev.Kind, ev.Drive.Letter)
		}
	}
}

// TestWatcher_WatchEvents_StartsAndCancels verifies the event-pump
// path:
//   - WatchEvents returns nil error → window class registered + HWND
//     created successfully.
//   - context cancellation closes the channel cleanly via the
//     WM_CLOSE → WM_DESTROY → WM_QUIT chain.
// Skips on hosts without an interactive session — RegisterClassExW
// works in service / SYSTEM contexts but the WM_DEVICECHANGE
// broadcast doesn't reach message-only windows there, which makes
// the test useless. The startup/teardown path is the only thing we
// verify automatically; live device-arrival reception is in the VM
// matrix.
func TestWatcher_WatchEvents_StartsAndCancels(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	w := NewWatcher(ctx, func(*Info) bool { return true })
	ch, err := w.WatchEvents(4)
	require.NoError(t, err)

	// Drain until the channel closes (ctx cancellation triggers
	// WM_CLOSE → WM_DESTROY → WM_QUIT → close(ch)).
	drained := 0
	for ev := range ch {
		drained++
		if ev.Err != nil {
			t.Logf("watcher error: %v", ev.Err)
		}
	}
	t.Logf("event-pump drained %d events", drained)
}
