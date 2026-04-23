package stealthopen

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandard_Open_ReturnsRealFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	want := []byte("hello stealthopen")
	require.NoError(t, os.WriteFile(path, want, 0o600))

	var op Opener = &Standard{}
	f, err := op.Open(path)
	require.NoError(t, err)
	defer f.Close()

	got, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestStandard_Open_MissingFile(t *testing.T) {
	var op Opener = &Standard{}
	_, err := op.Open(filepath.Join(t.TempDir(), "nope.bin"))
	require.Error(t, err)
}

func TestUse_NilReturnsStandard(t *testing.T) {
	op := Use(nil)
	require.NotNil(t, op)
	_, ok := op.(*Standard)
	assert.True(t, ok, "Use(nil) must return *Standard, got %T", op)
}

func TestUse_NonNilReturnsAsIs(t *testing.T) {
	in := &fakeOpener{}
	op := Use(in)
	assert.Same(t, in, op, "Use(x) must return x unchanged when x != nil")
}

func TestOpenRead_NilOpenerUsesStandard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob.bin")
	want := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	require.NoError(t, os.WriteFile(path, want, 0o600))

	got, err := OpenRead(nil, path)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestOpenRead_DelegatesToOpener(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob.bin")
	want := []byte("delegated-via-opener")
	require.NoError(t, os.WriteFile(path, want, 0o600))

	spy := &fakeOpener{}
	spy.file = openForRead(t, path)
	defer spy.file.Close()

	got, err := OpenRead(spy, path)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, []string{path}, spy.calls, "OpenRead must consult opener.Open once with the path")
}

func TestOpenRead_PropagatesOpenError(t *testing.T) {
	_, err := OpenRead(&Standard{}, filepath.Join(t.TempDir(), "nope.bin"))
	require.Error(t, err)
}

func openForRead(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	return f
}

// fakeOpener lets tests confirm Use() does not wrap non-nil values and
// lets consumer packages be exercised without hitting the filesystem.
type fakeOpener struct {
	calls []string
	file  *os.File
	err   error
}

func (f *fakeOpener) Open(path string) (*os.File, error) {
	f.calls = append(f.calls, path)
	return f.file, f.err
}
