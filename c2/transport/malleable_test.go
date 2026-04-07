package transport

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJQueryCDNProfile(t *testing.T) {
	p := JQueryCDN()
	assert.NotEmpty(t, p.GetURIs, "GetURIs should not be empty")
	assert.NotEmpty(t, p.PostURIs, "PostURIs should not be empty")
	assert.NotEmpty(t, p.UserAgent, "UserAgent should not be empty")
	assert.Contains(t, p.UserAgent, "Mozilla")
	assert.NotNil(t, p.DataEncoder, "DataEncoder should not be nil")
	assert.NotNil(t, p.DataDecoder, "DataDecoder should not be nil")
	assert.NotEmpty(t, p.Headers, "Headers should not be empty")
	assert.Contains(t, p.Headers["Referer"], "jquery")
}

func TestGoogleAPIProfile(t *testing.T) {
	p := GoogleAPI()
	assert.NotEmpty(t, p.GetURIs, "GetURIs should not be empty")
	assert.NotEmpty(t, p.PostURIs, "PostURIs should not be empty")
	assert.NotEmpty(t, p.UserAgent, "UserAgent should not be empty")
	assert.NotNil(t, p.DataEncoder, "DataEncoder should not be nil")
	assert.NotNil(t, p.DataDecoder, "DataDecoder should not be nil")
	assert.Contains(t, p.Headers["X-Goog-Api-Key"], "AIza")
}

func TestProfileDataEncoder(t *testing.T) {
	p := JQueryCDN()
	original := []byte("hello world")
	encoded := p.DataEncoder(original)
	assert.NotEqual(t, original, encoded, "encoded data should differ from original")

	decoded := p.DataDecoder(encoded)
	assert.Equal(t, original, decoded, "round-trip should recover original data")
}

func TestNewMalleable(t *testing.T) {
	p := JQueryCDN()
	m := NewMalleable("http://127.0.0.1:8080", 5*time.Second, p)
	require.NotNil(t, m)
	assert.Equal(t, "http://127.0.0.1:8080", m.address)
	assert.Equal(t, 5*time.Second, m.timeout)
	assert.Equal(t, p, m.profile)
}

func TestMalleable_WriteRead(t *testing.T) {
	// Echo server that returns the POST body on GET.
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			lastBody = body
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			if lastBody != nil {
				w.Write(lastBody) //nolint:errcheck
			}
		}
	}))
	defer srv.Close()

	p := JQueryCDN()
	m := NewMalleable(srv.URL, 5*time.Second, p)

	err := m.Connect(context.Background())
	require.NoError(t, err)
	defer m.Close()

	msg := []byte("C2 payload data")
	n, err := m.Write(msg)
	require.NoError(t, err)
	assert.Equal(t, len(msg), n)

	buf := make([]byte, 1024)
	n, err = m.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, msg, buf[:n])
}

func TestMalleable_ClosedPipe(t *testing.T) {
	p := JQueryCDN()
	m := NewMalleable("http://127.0.0.1:9999", 1*time.Second, p)
	m.closed = true

	_, err := m.Read(make([]byte, 10))
	assert.ErrorIs(t, err, io.ErrClosedPipe)

	_, err = m.Write([]byte("data"))
	assert.ErrorIs(t, err, io.ErrClosedPipe)
}

func TestMalleable_RemoteAddr(t *testing.T) {
	p := JQueryCDN()
	m := NewMalleable("127.0.0.1:8080", 1*time.Second, p)
	addr := m.RemoteAddr()
	assert.NotNil(t, addr)
	assert.Contains(t, addr.String(), "127.0.0.1")
}
