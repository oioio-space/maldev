package packer_test

import (
	"fmt"
	"os"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// ExamplePack is the Simple-tier round-trip via the blob
// pipeline (Phase 1a). Caller supplies a payload, gets back
// (blob, key); Unpack with the same key recovers the original.
func ExamplePack() {
	payload := []byte("hello packer")
	blob, key, err := packer.Pack(payload, packer.Options{
		Cipher: packer.CipherAESGCM,
	})
	if err != nil {
		return
	}
	got, err := packer.Unpack(blob, key)
	if err != nil {
		return
	}
	_ = got
}

// ExamplePackBinary shows the v0.61.0 UPX-style transform on a
// Linux ELF input. Output is single-binary; the kernel handles
// loading. Stage1Rounds=3 is the ship-tested baseline.
func ExamplePackBinary() {
	input, err := os.ReadFile("input.elf")
	if err != nil {
		return
	}
	out, key, err := packer.PackBinary(input, packer.PackBinaryOptions{
		Format:       packer.FormatLinuxELF,
		Stage1Rounds: 3,
		Seed:         time.Now().UnixNano(),
	})
	if err != nil {
		return
	}
	fmt.Printf("packed %d bytes (key %x...)\n", len(out), key[:8])
	_ = os.WriteFile("output.elf", out, 0o755)
}

// ExampleAddCoverPE chains the cover layer after a PackBinary
// call to inflate the PE static surface with three junk
// sections of mixed entropy.
func ExampleAddCoverPE() {
	packed, err := os.ReadFile("packed.exe")
	if err != nil {
		return
	}
	covered, err := packer.AddCoverPE(packed, packer.CoverOptions{
		JunkSections: []packer.JunkSection{
			{Name: ".rsrc", Size: 0x4000, Fill: packer.JunkFillRandom},
			{Name: ".pdata", Size: 0x2000, Fill: packer.JunkFillPattern},
			{Name: ".tls", Size: 0x1000, Fill: packer.JunkFillZero},
		},
	})
	if err != nil {
		return
	}
	_ = os.WriteFile("covered.exe", covered, 0o755)
}

// ExampleApplyDefaultCover is the one-liner cover layer.
// Auto-detects PE vs ELF and applies a 3-section default with
// randomized legit-looking names. Operators chain it after
// PackBinary; ELF static-PIE inputs return
// ErrCoverSectionTableFull and the operator falls back to the
// bare PackBinary output.
func ExampleApplyDefaultCover() {
	packed, err := os.ReadFile("packed.bin")
	if err != nil {
		return
	}
	out := packed
	if covered, err := packer.ApplyDefaultCover(packed, time.Now().UnixNano()); err == nil {
		out = covered
	}
	_ = os.WriteFile("output.bin", out, 0o755)
}

// ExamplePackShellcode shows the canonical operator flow for
// turning raw position-independent shellcode (msfvenom output,
// hand-rolled stage-1) into a runnable PE32+ or ELF64 binary.
//
// Two modes:
//
//   - Plain: smallest output (~400 B for 16-byte shellcode), no
//     decryption stub. The shellcode bytes sit at the entry point
//     in cleartext — trivially YARA-able. Use when stealth isn't
//     the concern or the shellcode is pre-encrypted upstream.
//   - Encrypted: ~8 KiB output, polymorphic SGN-style stub at the
//     entry point decrypts the shellcode in place and JMPs to it.
//     Same envelope the rest of the packer uses.
//
// On Linux the encrypted path is end-to-end VM-validated via
// TestPackShellcode_E2E_EncryptedELFExits42.
func ExamplePackShellcode() {
	// 17-byte Linux x86-64 exit_group(42).
	sc := []byte{
		0x48, 0xc7, 0xc0, 0xe7, 0x00, 0x00, 0x00, // mov rax, 231
		0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00, // mov rdi, 42
		0x0f, 0x05, // syscall
	}

	// Plain wrap — runnable, shellcode at e_entry in cleartext.
	plain, _, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format: packer.FormatLinuxELF,
	})
	if err != nil {
		return
	}
	_ = os.WriteFile("plain.elf", plain, 0o755)

	// Encrypted wrap — stub envelope, AEAD key returned for
	// out-of-band logging; the binary itself self-decrypts at run
	// time with the seed derived per pack.
	enc, key, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format:       packer.FormatLinuxELF,
		Encrypt:      true,
		Stage1Rounds: 3,
		Seed:         time.Now().UnixNano(),
	})
	if err != nil {
		return
	}
	_ = os.WriteFile("enc.elf", enc, 0o755)
	fmt.Printf("plain=%d enc=%d key=%x...\n", len(plain), len(enc), key[:4])
}
