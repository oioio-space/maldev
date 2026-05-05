package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// streamFactories runs the same test against AES-GCM and
// ChaCha20-Poly1305 — they share the underlying streamWriter /
// streamReader and any divergence would surface here.
type streamFactories struct {
	name      string
	keySize   int
	newWriter func(key []byte, w io.Writer) (io.WriteCloser, error)
	newReader func(key []byte, r io.Reader) (io.Reader, error)
}

func allFactories() []streamFactories {
	return []streamFactories{
		{"AES-GCM", 32, NewAESGCMWriter, NewAESGCMReader},
		{"ChaCha20-Poly1305", 32, NewChaCha20Writer, NewChaCha20Reader},
	}
}

func freshKey(t *testing.T, n int) []byte {
	t.Helper()
	return randBytes(t, n)
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// TestStreamWriter_RejectsBadKeySize covers the size validation
// for both factory pairs. Operators wiring the wrong key length
// should fail loud at construction, not at the first Write.
func TestStreamWriter_RejectsBadKeySize(t *testing.T) {
	for _, f := range allFactories() {
		t.Run(f.name, func(t *testing.T) {
			_, err := f.newWriter(make([]byte, f.keySize-1), &bytes.Buffer{})
			require.Error(t, err)
			_, err = f.newWriter(make([]byte, f.keySize+1), &bytes.Buffer{})
			require.Error(t, err)
			_, err = f.newReader(make([]byte, f.keySize-1), &bytes.Buffer{})
			require.Error(t, err)
		})
	}
}

// TestStream_RoundTripVariousSizes locks the core contract:
// for every realistic input length (empty, sub-chunk, exactly
// one chunk, multi-chunk including a partial trailing chunk),
// reader output equals writer input bytewise.
func TestStream_RoundTripVariousSizes(t *testing.T) {
	for _, f := range allFactories() {
		t.Run(f.name, func(t *testing.T) {
			sizes := []int{
				0,
				1,
				1023,
				streamChunkSize - 1,
				streamChunkSize,
				streamChunkSize + 1,
				3*streamChunkSize + 17, // 3 full chunks + partial
			}
			for _, n := range sizes {
				key := freshKey(t, f.keySize)
				plaintext := randBytes(t, n)

				var sink bytes.Buffer
				w, err := f.newWriter(key, &sink)
				require.NoError(t, err)
				_, err = w.Write(plaintext)
				require.NoError(t, err)
				require.NoError(t, w.Close())

				r, err := f.newReader(key, &sink)
				require.NoError(t, err)
				got, err := io.ReadAll(r)
				require.NoError(t, err)
				assert.Equal(t, plaintext, got, "size=%d", n)
			}
		})
	}
}

// TestStream_WriteAfterCloseFails guards the documented
// behaviour — once Close has emitted the final frame, the
// counter is consumed and no more frames may be appended.
func TestStream_WriteAfterCloseFails(t *testing.T) {
	for _, f := range allFactories() {
		t.Run(f.name, func(t *testing.T) {
			key := freshKey(t, f.keySize)
			w, err := f.newWriter(key, &bytes.Buffer{})
			require.NoError(t, err)
			require.NoError(t, w.Close())

			_, err = w.Write([]byte("post-close"))
			require.ErrorIs(t, err, ErrStreamWriteAfterClose)
		})
	}
}

// TestStream_CloseIsIdempotent — a defer chain that double-
// closes (e.g. explicit Close + deferred Close) must not
// double-flush a final frame.
func TestStream_CloseIsIdempotent(t *testing.T) {
	for _, f := range allFactories() {
		t.Run(f.name, func(t *testing.T) {
			key := freshKey(t, f.keySize)
			var sink bytes.Buffer
			w, err := f.newWriter(key, &sink)
			require.NoError(t, err)
			require.NoError(t, w.Close())
			before := sink.Len()
			require.NoError(t, w.Close())
			assert.Equal(t, before, sink.Len(),
				"second Close must not write")
		})
	}
}

// TestStream_TruncatedStreamErrors — the reader must surface
// ErrStreamTruncated when the underlying io.Reader EOFs before
// a final-marked frame arrives. Truncation is the canonical
// network-loss / attacker-cut signature; conflating it with
// EOF would silently accept a partial decryption.
func TestStream_TruncatedStreamErrors(t *testing.T) {
	for _, f := range allFactories() {
		t.Run(f.name, func(t *testing.T) {
			key := freshKey(t, f.keySize)
			plaintext := randBytes(t, 3*streamChunkSize+100)

			var sink bytes.Buffer
			w, err := f.newWriter(key, &sink)
			require.NoError(t, err)
			_, err = w.Write(plaintext)
			require.NoError(t, err)
			require.NoError(t, w.Close())

			// Cut the last 50 bytes — truncates the body of the
			// final frame (size of the body is much larger than 50,
			// so the header lands intact). io.ReadFull on the body
			// returns io.ErrUnexpectedEOF → ErrStreamTruncated.
			truncated := sink.Bytes()[:sink.Len()-50]

			r, err := f.newReader(key, bytes.NewReader(truncated))
			require.NoError(t, err)
			_, err = io.ReadAll(r)
			require.ErrorIs(t, err, ErrStreamTruncated)
		})
	}
}

// TestStream_TamperedFrameFailsAuth — flipping a single
// ciphertext bit must trigger Open failure on that frame.
// Authenticated encryption's whole point.
func TestStream_TamperedFrameFailsAuth(t *testing.T) {
	for _, f := range allFactories() {
		t.Run(f.name, func(t *testing.T) {
			key := freshKey(t, f.keySize)
			plaintext := randBytes(t, 100)

			var sink bytes.Buffer
			w, err := f.newWriter(key, &sink)
			require.NoError(t, err)
			_, err = w.Write(plaintext)
			require.NoError(t, err)
			require.NoError(t, w.Close())

			// Flip a bit deep inside the ciphertext (skip the
			// 4-byte header at offset 0).
			tampered := append([]byte(nil), sink.Bytes()...)
			tampered[10] ^= 0x40

			r, err := f.newReader(key, bytes.NewReader(tampered))
			require.NoError(t, err)
			_, err = io.ReadAll(r)
			require.Error(t, err,
				"AEAD must reject a flipped ciphertext bit")
		})
	}
}

// TestStream_WrongKeyFailsAuth — a reader instantiated with a
// different key must fail Open on the first frame.
func TestStream_WrongKeyFailsAuth(t *testing.T) {
	for _, f := range allFactories() {
		t.Run(f.name, func(t *testing.T) {
			writeKey := freshKey(t, f.keySize)
			readKey := freshKey(t, f.keySize)

			var sink bytes.Buffer
			w, err := f.newWriter(writeKey, &sink)
			require.NoError(t, err)
			_, err = w.Write([]byte("payload"))
			require.NoError(t, err)
			require.NoError(t, w.Close())

			r, err := f.newReader(readKey, &sink)
			require.NoError(t, err)
			_, err = io.ReadAll(r)
			require.Error(t, err,
				"reader with wrong key must fail Open")
		})
	}
}

// TestStream_ChunkBoundaryRoundTrip exercises the writer's
// internal flush logic at the exact chunk boundary by writing
// in single-byte increments. Catches bugs where the per-Write
// loop miscounts when room == 0.
func TestStream_ChunkBoundaryRoundTrip(t *testing.T) {
	for _, f := range allFactories() {
		t.Run(f.name, func(t *testing.T) {
			key := freshKey(t, f.keySize)
			plaintext := make([]byte, streamChunkSize+5)
			for i := range plaintext {
				plaintext[i] = byte(i)
			}

			var sink bytes.Buffer
			w, err := f.newWriter(key, &sink)
			require.NoError(t, err)
			for _, b := range plaintext {
				n, err := w.Write([]byte{b})
				require.NoError(t, err)
				require.Equal(t, 1, n)
			}
			require.NoError(t, w.Close())

			r, err := f.newReader(key, &sink)
			require.NoError(t, err)
			got, err := io.ReadAll(r)
			require.NoError(t, err)
			assert.Equal(t, plaintext, got)
		})
	}
}

// TestStream_NoCloseCallProducesTruncatedReader — operators
// who forget Close should get a clear error, not silent
// success on an incomplete stream. The reader will see the
// frames that DID land but error at the end because no
// final-marked frame ever arrives.
func TestStream_NoCloseCallProducesTruncatedReader(t *testing.T) {
	for _, f := range allFactories() {
		t.Run(f.name, func(t *testing.T) {
			key := freshKey(t, f.keySize)
			plaintext := randBytes(t, 2*streamChunkSize) // 2 full chunks

			var sink bytes.Buffer
			w, err := f.newWriter(key, &sink)
			require.NoError(t, err)
			_, err = w.Write(plaintext)
			require.NoError(t, err)
			// NB: no w.Close() — simulates operator error.

			r, err := f.newReader(key, &sink)
			require.NoError(t, err)
			_, err = io.ReadAll(r)
			require.ErrorIs(t, err, ErrStreamTruncated,
				"missing-final-frame must surface as ErrStreamTruncated")
		})
	}
}
