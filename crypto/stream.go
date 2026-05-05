package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// streamChunkSize is the plaintext chunk size of a stream frame.
// 64 KiB hits the sweet spot of "small enough to bound peak
// memory" + "large enough that the per-frame 16-byte AEAD tag
// overhead is < 0.03%". Operators wiring a custom chunk size
// would have to fork the package — keeping this internal forces
// reader/writer compatibility.
const streamChunkSize = 64 * 1024

// streamMaxFrame caps the on-the-wire sealed-bytes length the
// reader will accept. Bounded by the high-bit-flag in the frame
// header — see [streamWriter.flushChunk].
const streamMaxFrame uint32 = 0x7FFFFFFF

// streamFinalBit is the high bit of the 4-byte header. Set on
// the last frame; the AEAD authenticates it via the AAD so a
// flipped bit is caught by the next Open call.
const streamFinalBit uint32 = 0x80000000

// ErrStreamTruncated is returned by stream readers when the
// underlying io.Reader hits EOF before a final-marked frame
// arrives — the prefix of a legit stream that was cut short
// (operator error, network drop, attacker truncation).
var ErrStreamTruncated = errors.New("crypto: stream truncated before final frame")

// ErrStreamWriteAfterClose is returned by stream writers when
// Write is called after Close. Once Close has flushed the final
// frame the counter is consumed; re-opening a closed writer
// would either reuse the final frame's AAD (rejection by reader)
// or produce a misordered stream.
var ErrStreamWriteAfterClose = errors.New("crypto: stream write after Close")

// NewAESGCMWriter returns an [io.WriteCloser] that encrypts
// every Write through AES-256-GCM and frames it onto w. Key
// must be 32 bytes. Caller MUST Close — the final frame is
// emitted there and the receiver will reject the stream as
// truncated otherwise.
//
// Frame layout (per chunk, on the wire):
//
//	[4-byte BE header: bit 31 = final, bits 0-30 = sealed length]
//	[sealed bytes (ciphertext + 16-byte tag)]
//
// The AEAD AAD is the 8-byte BE chunk counter + 1 byte
// (0 = more, 1 = final). A reader sees malleability or
// out-of-order frames as authentication failures.
//
// Suitable for multi-MB / multi-GB payloads — peak memory is
// bounded by [streamChunkSize] (64 KiB plaintext + 16-byte tag).
func NewAESGCMWriter(key []byte, w io.Writer) (io.WriteCloser, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: AES-GCM key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return newStreamWriter(aead, w), nil
}

// NewAESGCMReader returns an [io.Reader] that consumes the
// frame stream produced by [NewAESGCMWriter] and yields
// plaintext. Decryption / authentication failures surface as
// errors on the next Read; truncation surfaces as
// [ErrStreamTruncated].
func NewAESGCMReader(key []byte, r io.Reader) (io.Reader, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: AES-GCM key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return newStreamReader(aead, r), nil
}

// NewChaCha20Writer returns the XChaCha20-Poly1305 streaming
// counterpart of [NewAESGCMWriter]. Key must be 32 bytes; the
// underlying nonce is XChaCha20's 192-bit nonce derived from
// the chunk counter (the high 24 bytes are zero, low 8 bytes
// are the BE counter — same composition strategy as the
// AES-GCM stream uses for its 96-bit nonce).
//
// Prefer this over the AES-GCM variant on hosts without
// AES-NI: XChaCha20 is software-friendly and bypasses the
// AES-key-schedule cost entirely.
func NewChaCha20Writer(key []byte, w io.Writer) (io.WriteCloser, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("crypto: ChaCha20 key must be %d bytes, got %d",
			chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return newStreamWriter(aead, w), nil
}

// NewChaCha20Reader returns the [NewChaCha20Writer] counterpart.
func NewChaCha20Reader(key []byte, r io.Reader) (io.Reader, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("crypto: ChaCha20 key must be %d bytes, got %d",
			chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return newStreamReader(aead, r), nil
}

// streamWriter accumulates plaintext into a chunk buffer and
// flushes a sealed frame whenever it fills (or on Close, with
// the final flag set). Nonce / AAD / sealed buffers live on the
// struct so the per-frame hot path doesn't allocate.
type streamWriter struct {
	aead      cipher.AEAD
	w         io.Writer
	buf       []byte                                // chunk accumulator (len ≤ streamChunkSize)
	sealBuf   []byte                                // reused Seal destination (cap = chunk + Overhead)
	nonceBuf  [chacha20poly1305.NonceSizeX]byte     // 24-byte ceiling; sliced to aead.NonceSize()
	aadBuf    [streamAADSize]byte
	nonceSize int
	counter   uint64
	closed    bool
}

// streamAADSize is the wire size of the AAD: 8-byte BE counter + 1 byte final flag.
const streamAADSize = 9

func newStreamWriter(aead cipher.AEAD, w io.Writer) *streamWriter {
	return &streamWriter{
		aead:      aead,
		w:         w,
		buf:       make([]byte, 0, streamChunkSize),
		sealBuf:   make([]byte, 0, streamChunkSize+aead.Overhead()),
		nonceSize: aead.NonceSize(),
	}
}

// Write appends p to the chunk buffer, flushing whole chunks as
// it fills. Returns the number of plaintext bytes consumed.
func (s *streamWriter) Write(p []byte) (int, error) {
	if s.closed {
		return 0, ErrStreamWriteAfterClose
	}
	written := 0
	for len(p) > 0 {
		room := streamChunkSize - len(s.buf)
		if room == 0 {
			if err := s.flushChunk(false); err != nil {
				return written, err
			}
			continue
		}
		take := room
		if take > len(p) {
			take = len(p)
		}
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
		written += take
	}
	return written, nil
}

// Close flushes the partial buffer (or an empty plaintext when
// nothing is buffered) as the final frame. Idempotent.
func (s *streamWriter) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.flushChunk(true)
}

func (s *streamWriter) flushChunk(final bool) error {
	nonce := s.fillNonce()
	aad := s.fillAAD(final)
	sealed := s.aead.Seal(s.sealBuf[:0], nonce, s.buf, aad)
	s.buf = s.buf[:0]

	header := uint32(len(sealed))
	if final {
		header |= streamFinalBit
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], header)
	if _, err := s.w.Write(hdr[:]); err != nil {
		s.closed = true // poison — partial frame on the wire
		return err
	}
	if _, err := s.w.Write(sealed); err != nil {
		s.closed = true
		return err
	}
	s.counter++
	return nil
}

func (s *streamWriter) fillNonce() []byte {
	nonce := s.nonceBuf[:s.nonceSize]
	for i := range nonce[:len(nonce)-8] {
		nonce[i] = 0
	}
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], s.counter)
	return nonce
}

func (s *streamWriter) fillAAD(final bool) []byte {
	binary.BigEndian.PutUint64(s.aadBuf[:8], s.counter)
	s.aadBuf[8] = 0
	if final {
		s.aadBuf[8] = 1
	}
	return s.aadBuf[:]
}

// streamReader is the per-frame consumer. plain holds the
// decrypted bytes of the most recent frame (reused across
// frames); plainR is the read cursor. seenFinal turns
// subsequent Reads into io.EOF.
type streamReader struct {
	aead         cipher.AEAD
	r            io.Reader
	plain        []byte                                // reused Open destination
	sealBuf      []byte                                // reused sealed-bytes buffer
	nonceBuf     [chacha20poly1305.NonceSizeX]byte
	aadBuf       [streamAADSize]byte
	nonceSize    int
	maxSealedLen uint32 // header-length cap, prevents attacker-driven 2 GiB allocs
	counter      uint64
	plainR       int
	seenFinal    bool
}

func newStreamReader(aead cipher.AEAD, r io.Reader) *streamReader {
	overhead := aead.Overhead()
	return &streamReader{
		aead:         aead,
		r:            r,
		sealBuf:      make([]byte, 0, streamChunkSize+overhead),
		plain:        make([]byte, 0, streamChunkSize),
		nonceSize:    aead.NonceSize(),
		maxSealedLen: uint32(streamChunkSize + overhead),
	}
}

// Read returns plaintext bytes, fetching + decrypting frames
// from the underlying reader on demand. Returns io.EOF after
// the final-marked frame is consumed; returns
// [ErrStreamTruncated] when the underlying reader EOFs before
// that frame.
func (s *streamReader) Read(p []byte) (int, error) {
	for s.plainR >= len(s.plain) {
		if s.seenFinal {
			return 0, io.EOF
		}
		if err := s.fillNext(); err != nil {
			return 0, err
		}
	}
	n := copy(p, s.plain[s.plainR:])
	s.plainR += n
	return n, nil
}

func (s *streamReader) fillNext() error {
	var hdr [4]byte
	if _, err := io.ReadFull(s.r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrStreamTruncated
		}
		return err
	}
	h := binary.BigEndian.Uint32(hdr[:])
	final := h&streamFinalBit != 0
	length := h & streamMaxFrame

	if length > s.maxSealedLen {
		return fmt.Errorf("crypto: frame %d length %d exceeds max %d (DoS guard)",
			s.counter, length, s.maxSealedLen)
	}

	if cap(s.sealBuf) < int(length) {
		s.sealBuf = make([]byte, length)
	}
	sealed := s.sealBuf[:length]
	if _, err := io.ReadFull(s.r, sealed); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrStreamTruncated
		}
		return err
	}

	nonce := s.fillNonce()
	aad := s.fillAAD(final)
	plain, err := s.aead.Open(s.plain[:0], nonce, sealed, aad)
	if err != nil {
		return fmt.Errorf("crypto: frame %d open failed: %w", s.counter, err)
	}
	s.counter++
	s.plain = plain
	s.plainR = 0
	if final {
		s.seenFinal = true
	}
	return nil
}

func (s *streamReader) fillNonce() []byte {
	nonce := s.nonceBuf[:s.nonceSize]
	for i := range nonce[:len(nonce)-8] {
		nonce[i] = 0
	}
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], s.counter)
	return nonce
}

func (s *streamReader) fillAAD(final bool) []byte {
	binary.BigEndian.PutUint64(s.aadBuf[:8], s.counter)
	s.aadBuf[8] = 0
	if final {
		s.aadBuf[8] = 1
	}
	return s.aadBuf[:]
}
