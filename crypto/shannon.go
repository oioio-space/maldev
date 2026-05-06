package crypto

import "math"

// ShannonEntropy returns the byte-histogram Shannon entropy of
// `data` in bits/byte, in the range [0, 8].
//
// Reference points operators tune detections against:
//
//   - 8.0 — uniform random (AEAD ciphertext, compressed data,
//     properly encrypted shellcode).
//   - 7.5+ — typical YARA `entropy >= 7.5` flag threshold.
//   - 5.5–6.5 — real `.text` sections in Windows EXEs.
//   - 4.5–5.5 — ASCII text, base64-encoded data.
//   - 0 — runs of identical bytes.
//
// Use this to instrument anti-entropy work (the
// [github.com/oioio-space/maldev/pe/packer.OpEntropyCover]
// pipeline op) or to score sandbox / packed-binary detections.
//
// Empty input returns 0.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var hist [256]int
	for _, b := range data {
		hist[b]++
	}
	total := float64(len(data))
	var h float64
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}
