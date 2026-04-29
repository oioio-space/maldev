package stealthopen

import (
	"bytes"
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

func TestUseCreator_NilReturnsStandard(t *testing.T) {
	c := UseCreator(nil)
	if _, ok := c.(*StandardCreator); !ok {
		t.Fatalf("UseCreator(nil) = %T, want *StandardCreator", c)
	}
}

func TestUseCreator_PassthroughOnNonNil(t *testing.T) {
	fc := &fakeCreator{}
	if got := UseCreator(fc); got != fc {
		t.Fatalf("UseCreator(non-nil) = %v, want passthrough %v", got, fc)
	}
}

func TestStandardCreator_CreateWritesToDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smoke.bin")
	wc, err := (&StandardCreator{}).Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := wc.Write([]byte("ok")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := wc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(b) != "ok" {
		t.Errorf("contents = %q, want %q", b, "ok")
	}
}

// fakeCreator records Create calls so consumer tests can assert WriteVia
// routed through the operator's primitive.
type fakeCreator struct {
	paths []string
	wc    io.WriteCloser
	err   error
}

func (f *fakeCreator) Create(path string) (io.WriteCloser, error) {
	f.paths = append(f.paths, path)
	return f.wc, f.err
}

func TestWriteAll_NilCreatorWritesViaStandard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "all.bin")
	if err := WriteAll(nil, path, []byte("hello")); err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("contents = %q, want %q", got, "hello")
	}
}

func TestWriteAll_DelegatesToCreator(t *testing.T) {
	var buf recordingWriteCloser
	fc := &fakeCreator{wc: &buf}
	const path = `C:\fake\out.bin`
	if err := WriteAll(fc, path, []byte("payload")); err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	if len(fc.paths) != 1 || fc.paths[0] != path {
		t.Errorf("Create paths = %v, want [%q]", fc.paths, path)
	}
	if !buf.closed {
		t.Error("Close not called on the WriteCloser returned by Create")
	}
	if buf.String() != "payload" {
		t.Errorf("written = %q, want %q", buf.String(), "payload")
	}
}

func TestWriteAll_PropagatesCreateError(t *testing.T) {
	wantErr := errCreateFailed
	fc := &fakeCreator{err: wantErr}
	if err := WriteAll(fc, "x", []byte("y")); err != wantErr {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

// recordingWriteCloser is a bytes.Buffer with a Close that records
// invocation order — lets WriteAll tests verify Close was called.
type recordingWriteCloser struct {
	bytes.Buffer
	closed bool
}

func (r *recordingWriteCloser) Close() error { r.closed = true; return nil }

var errCreateFailed = stubError("stealthopen_test: create failed")

type stubError string

func (s stubError) Error() string { return string(s) }
