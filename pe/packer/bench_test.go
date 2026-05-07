package packer_test

import (
	"os"
	"path/filepath"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// BenchmarkPackBinary_LinuxELF measures end-to-end PackBinary
// throughput on the real Phase 1f Stage E fixture (~1.3 MB Go
// static-PIE binary). Reports B/op + MB/s so operators can
// budget pack-time cost in CI / build pipelines.
//
// Run with:
//
//	go test -bench=PackBinary_LinuxELF -benchmem ./pe/packer/
func BenchmarkPackBinary_LinuxELF(b *testing.B) {
	input, err := os.ReadFile(filepath.Join("runtime", "testdata", "hello_static_pie"))
	if err != nil {
		b.Fatalf("read fixture: %v", err)
	}
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
			Format:       packerpkg.FormatLinuxELF,
			Stage1Rounds: 3,
			Seed:         int64(i + 1),
		})
		if err != nil {
			b.Fatalf("PackBinary: %v", err)
		}
	}
}

// BenchmarkPackBinary_VaryRounds quantifies the cost of additional
// SGN decoder rounds — operators trading polymorphism strength
// against pack-time can read this number directly.
func BenchmarkPackBinary_VaryRounds(b *testing.B) {
	input, err := os.ReadFile(filepath.Join("runtime", "testdata", "hello_static_pie"))
	if err != nil {
		b.Fatalf("read fixture: %v", err)
	}
	for _, rounds := range []int{1, 3, 5, 7} {
		b.Run(roundsLabel(rounds), func(sub *testing.B) {
			sub.SetBytes(int64(len(input)))
			sub.ResetTimer()
			for i := 0; i < sub.N; i++ {
				_, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
					Format:       packerpkg.FormatLinuxELF,
					Stage1Rounds: rounds,
					Seed:         int64(i + 1),
				})
				if err != nil {
					sub.Fatalf("PackBinary: %v", err)
				}
			}
		})
	}
}

// BenchmarkAddCoverPE_DefaultCover times the cover layer alone
// against a synthetic PE32+ — isolates AddCoverPE from PackBinary
// so the cover-layer cost can be measured independently.
func BenchmarkAddCoverPE_DefaultCover(b *testing.B) {
	input := minimalPE32Plus(0x800)
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := packerpkg.ApplyDefaultCover(input, int64(i+1))
		if err != nil {
			b.Fatalf("ApplyDefaultCover: %v", err)
		}
	}
}

func roundsLabel(n int) string {
	switch n {
	case 1:
		return "1round"
	case 3:
		return "3rounds"
	case 5:
		return "5rounds"
	case 7:
		return "7rounds"
	}
	return "Nrounds"
}
