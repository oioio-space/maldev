//go:build windows

package ads

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tempFile(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "ads_test_*.txt")
	require.NoError(t, err)
	f.Write([]byte("main stream content"))
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestWriteAndRead(t *testing.T) {
	path := tempFile(t)
	payload := []byte("secret ADS payload")

	err := Write(path, "hidden", payload)
	require.NoError(t, err)

	got, err := Read(path, "hidden")
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestList(t *testing.T) {
	path := tempFile(t)

	require.NoError(t, Write(path, "stream1", []byte("aaa")))
	require.NoError(t, Write(path, "stream2", []byte("bbbbbb")))

	streams, err := List(path)
	require.NoError(t, err)

	names := make([]string, len(streams))
	for i, s := range streams {
		names[i] = s.Name
	}
	assert.Contains(t, names, "stream1")
	assert.Contains(t, names, "stream2")
}

func TestDelete(t *testing.T) {
	path := tempFile(t)

	require.NoError(t, Write(path, "todelete", []byte("data")))
	require.NoError(t, Delete(path, "todelete"))

	_, err := Read(path, "todelete")
	assert.Error(t, err, "reading a deleted ADS should fail")
}

func TestReadNonexistent(t *testing.T) {
	path := tempFile(t)
	_, err := Read(path, "nonexistent")
	assert.Error(t, err)
}

func TestDeleteNonexistent(t *testing.T) {
	path := tempFile(t)
	err := Delete(path, "nonexistent")
	assert.Error(t, err)
}

func TestWriteEmptyStream(t *testing.T) {
	path := tempFile(t)
	err := Write(path, "empty", []byte{})
	require.NoError(t, err)

	got, err := Read(path, "empty")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListOnFileWithNoADS(t *testing.T) {
	path := tempFile(t)
	streams, err := List(path)
	require.NoError(t, err)
	assert.Empty(t, streams, "no alternate streams should be listed")
}

func TestCreateUndeletable(t *testing.T) {
	dir := t.TempDir()

	path, err := CreateUndeletable(dir, []byte("hidden payload"))
	require.NoError(t, err)
	t.Logf("Created undeletable file: %s", path)

	// Verify the file exists and contains our data.
	data, err := ReadUndeletable(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("hidden payload"), data)

	// Verify the name uses the trailing dots trick.
	assert.Contains(t, path, "...", "path should use reserved name trick")
}

func TestCreateUndeletableEmpty(t *testing.T) {
	dir := t.TempDir()

	// Empty payload should still create the file without error.
	path, err := CreateUndeletable(dir, nil)
	require.NoError(t, err)

	data, err := ReadUndeletable(path)
	require.NoError(t, err)
	assert.Empty(t, data)
}
