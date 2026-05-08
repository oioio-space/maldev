package packer

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
)

// Add a compression step to the pipeline. The Algo byte selects
// which compressor (the same Compressor enum already declared in
// format.go).
//
// Compression must run BEFORE encryption — encrypted data is
// near-uniform entropy and compresses to near-original size.
// Pack runs steps in order, so place the compression step EARLY
// in the pipeline.
//
//	pipeline := []packer.PipelineStep{
//	    {Op: packer.OpCompress, Algo: uint8(packer.CompressorFlate)},
//	    {Op: packer.OpCipher,   Algo: uint8(packer.CipherAESGCM)},
//	}
const OpCompress PipelineOp = 3

// compressionPrefixSize is the byte count of the original-size
// header we prepend to compressed output. Stored as a uint32 LE
// so the decompressor can pre-allocate the output buffer + sanity-
// check the inflated length matches.
const compressionPrefixSize = 4

// applyCompression runs ONE compression step forward.
//
// Compression doesn't take an external key — there's no secret
// to derive. Returns the compressed bytes + an empty key so the
// pipeline's per-step key slot is uniformly populated even for
// keyless steps (the empty slice signals "no key needed").
func applyCompression(c Compressor, data []byte) (out []byte, _ []byte, err error) {
	// Pre-grow to the worst-case compressed size (input + prefix).
	// Eliminates the doubling-realloc churn that bytes.Buffer's
	// default 64-byte starting capacity inflicts on MB-scale .text
	// sections. Real compression usually shrinks the output well
	// below this; the over-allocation is freed on return.
	buf := bytes.Buffer{}
	buf.Grow(compressionPrefixSize + len(data))
	if err := binary.Write(&buf, binary.LittleEndian, uint32(len(data))); err != nil {
		return nil, nil, err
	}

	switch c {
	case CompressorNone:
		buf.Write(data)
	case CompressorFlate:
		w, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			return nil, nil, err
		}
		if _, err := w.Write(data); err != nil {
			return nil, nil, err
		}
		if err := w.Close(); err != nil {
			return nil, nil, err
		}
	case CompressorGzip:
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(data); err != nil {
			return nil, nil, err
		}
		if err := w.Close(); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedCompressor, c)
	}
	return buf.Bytes(), nil, nil
}

// reverseCompression runs ONE decompression step.
func reverseCompression(c Compressor, data []byte) ([]byte, error) {
	if len(data) < compressionPrefixSize {
		return nil, fmt.Errorf("%w: compressed body shorter than 4-byte size prefix", ErrPayloadSizeMismatch)
	}
	wantSize := binary.LittleEndian.Uint32(data[:compressionPrefixSize])
	body := data[compressionPrefixSize:]

	var out []byte
	switch c {
	case CompressorNone:
		out = body
	case CompressorFlate:
		r := flate.NewReader(bytes.NewReader(body))
		defer r.Close()
		// Pre-allocate to wantSize so io.ReadAll's doubling
		// strategy doesn't churn through log2(size/512) reallocs
		// on multi-MB payloads.
		buf := bytes.NewBuffer(make([]byte, 0, wantSize))
		if _, err := io.Copy(buf, r); err != nil {
			return nil, fmt.Errorf("packer: flate decompress: %w", err)
		}
		out = buf.Bytes()
	case CompressorGzip:
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("packer: gzip header: %w", err)
		}
		defer r.Close()
		buf := bytes.NewBuffer(make([]byte, 0, wantSize))
		if _, err := io.Copy(buf, r); err != nil {
			return nil, fmt.Errorf("packer: gzip decompress: %w", err)
		}
		out = buf.Bytes()
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCompressor, c)
	}

	if uint32(len(out)) != wantSize {
		return nil, fmt.Errorf("%w: decompressed %d bytes, prefix says %d",
			ErrPayloadSizeMismatch, len(out), wantSize)
	}
	return out, nil
}

