package packer_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestPipeline_RoundTrip_Compression_AllAlgos verifies each
// shipped compressor round-trips standalone (no cipher) — the
// pipeline is just a single OpCompress step.
func TestPipeline_RoundTrip_Compression_AllAlgos(t *testing.T) {
	cases := []struct {
		name string
		algo packer.Compressor
	}{
		{"none", packer.CompressorNone},
		{"flate", packer.CompressorFlate},
		{"gzip", packer.CompressorGzip},
	}
	input := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog ", 50))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob, keys, err := packer.PackPipeline(input, []packer.PipelineStep{
				{Op: packer.OpCompress, Algo: uint8(tc.algo)},
			})
			if err != nil {
				t.Fatalf("PackPipeline(%s): %v", tc.algo, err)
			}
			got, err := packer.UnpackPipeline(blob, keys)
			if err != nil {
				t.Fatalf("UnpackPipeline(%s): %v", tc.algo, err)
			}
			if !bytes.Equal(got, input) {
				t.Errorf("%s: round-trip lost bytes", tc.algo)
			}
		})
	}
}

// TestPipeline_Compression_ActuallyShrinks verifies that
// CompressorFlate / CompressorGzip applied to highly-repetitive
// input produce a SMALLER blob than the same input through
// CompressorNone.
func TestPipeline_Compression_ActuallyShrinks(t *testing.T) {
	// Highly compressible input: repeated dictionary phrase.
	input := []byte(strings.Repeat("AAAA", 1024)) // 4 KB of 'A'

	noneBlob, _, _ := packer.PackPipeline(input, []packer.PipelineStep{
		{Op: packer.OpCompress, Algo: uint8(packer.CompressorNone)},
	})
	flateBlob, _, _ := packer.PackPipeline(input, []packer.PipelineStep{
		{Op: packer.OpCompress, Algo: uint8(packer.CompressorFlate)},
	})

	if len(flateBlob) >= len(noneBlob) {
		t.Errorf("flate blob (%d) not smaller than none blob (%d) — compression ineffective",
			len(flateBlob), len(noneBlob))
	}
	t.Logf("4KB AAAA: none=%d bytes, flate=%d bytes (%.1f%% reduction)",
		len(noneBlob), len(flateBlob),
		100*(1-float64(len(flateBlob))/float64(len(noneBlob))))
}

// TestPipeline_RoundTrip_CompressThenEncrypt is the canonical
// real-world stack: compress first (max compression on plaintext),
// then encrypt (post-compression bytes look random).
func TestPipeline_RoundTrip_CompressThenEncrypt(t *testing.T) {
	input := []byte(strings.Repeat("Pack this with multiple layers ", 100))
	pipeline := []packer.PipelineStep{
		{Op: packer.OpCompress, Algo: uint8(packer.CompressorFlate)},
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)},
	}
	blob, keys, err := packer.PackPipeline(input, pipeline)
	if err != nil {
		t.Fatalf("PackPipeline: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	// Compression step has no key — should be nil.
	if keys[0] != nil {
		t.Errorf("compression step key = %v, want nil (no secret needed)", keys[0])
	}
	// Cipher step has a key.
	if len(keys[1]) == 0 {
		t.Error("cipher step key is empty")
	}
	got, err := packer.UnpackPipeline(blob, keys)
	if err != nil {
		t.Fatalf("UnpackPipeline: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Error("compress+encrypt round-trip lost bytes")
	}
}

// TestCompressor_RejectsUnimplemented confirms the reserved
// constants (aPLib / LZMA / Zstd / LZ4) surface a clean error
// rather than silently producing garbage.
func TestCompressor_RejectsUnimplemented(t *testing.T) {
	cases := []packer.Compressor{
		packer.CompressorAPLib,
		packer.CompressorLZMA,
		packer.CompressorZstd,
		packer.CompressorLZ4,
	}
	for _, c := range cases {
		t.Run(c.String(), func(t *testing.T) {
			_, _, err := packer.PackPipeline([]byte("x"), []packer.PipelineStep{
				{Op: packer.OpCompress, Algo: uint8(c)},
			})
			if !errors.Is(err, packer.ErrUnsupportedCompressor) {
				t.Errorf("%s: got %v, want ErrUnsupportedCompressor", c, err)
			}
		})
	}
}

func TestOpCompress_String(t *testing.T) {
	if got := packer.OpCompress.String(); got != "compress" {
		t.Errorf("OpCompress.String() = %q, want %q", got, "compress")
	}
}

func TestCompressor_StringExtended(t *testing.T) {
	cases := []struct {
		c    packer.Compressor
		want string
	}{
		{packer.CompressorFlate, "flate"},
		{packer.CompressorGzip, "gzip"},
	}
	for _, tc := range cases {
		if got := tc.c.String(); got != tc.want {
			t.Errorf("Compressor(%d).String() = %q, want %q", uint8(tc.c), got, tc.want)
		}
	}
}
