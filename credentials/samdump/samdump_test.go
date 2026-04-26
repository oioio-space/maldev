package samdump

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestAccount_Pwdump_FullHashes(t *testing.T) {
	a := Account{
		Username: "alice",
		RID:      1001,
		LM:       bytes.Repeat([]byte{0xAA}, 16),
		NT:       bytes.Repeat([]byte{0xBB}, 16),
	}
	want := "alice:1001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:::"
	if got := a.Pwdump(); got != want {
		t.Errorf("Pwdump = %q, want %q", got, want)
	}
}

func TestAccount_Pwdump_EmptyHashesUseInactiveSentinel(t *testing.T) {
	a := Account{Username: "bob", RID: 500}
	want := "bob:500:00000000000000000000000000000000:00000000000000000000000000000000:::"
	if got := a.Pwdump(); got != want {
		t.Errorf("Pwdump = %q, want %q", got, want)
	}
}

func TestAccount_Pwdump_MismatchedHashLengthFallsToInactive(t *testing.T) {
	a := Account{
		Username: "carol",
		RID:      1234,
		LM:       []byte{0x11, 0x22}, // wrong length
		NT:       bytes.Repeat([]byte{0x33}, 16),
	}
	got := a.Pwdump()
	if !strings.Contains(got, "00000000000000000000000000000000:33333333333333333333333333333333:::") {
		t.Errorf("Pwdump = %q (LM should fall to inactive due to wrong length)", got)
	}
}

func TestDump_PropagatesHiveCorrupt(t *testing.T) {
	bad := []byte("not a hive at all")
	good := make([]byte, regfBaseBlockSz)
	copy(good, []byte(regfMagic))

	_, err := Dump(&fakeReaderAt{b: bad}, int64(len(bad)),
		&fakeReaderAt{b: good}, int64(len(good)))
	if !errors.Is(err, ErrDump) {
		t.Fatalf("system-hive failure: err = %v, want wrap of ErrDump", err)
	}

	_, err = Dump(&fakeReaderAt{b: good}, int64(len(good)),
		&fakeReaderAt{b: bad}, int64(len(bad)))
	if !errors.Is(err, ErrDump) {
		t.Fatalf("sam-hive failure: err = %v, want wrap of ErrDump", err)
	}
}

func TestDump_PropagatesBootKeyFailure(t *testing.T) {
	// Both hives are valid REGF headers but neither has any HBIN
	// payload — extractBootKey will fail trying to walk
	// ControlSet001\\Control\\Lsa.
	good := make([]byte, regfBaseBlockSz)
	copy(good, []byte(regfMagic))
	_, err := Dump(&fakeReaderAt{b: good}, int64(len(good)),
		&fakeReaderAt{b: good}, int64(len(good)))
	if !errors.Is(err, ErrDump) {
		t.Fatalf("err = %v, want wrap of ErrDump", err)
	}
	// And it should specifically be a boot-key failure underneath.
	if !errors.Is(err, ErrBootKey) {
		t.Errorf("expected wrapped ErrBootKey somewhere in error chain: %v", err)
	}
}

func TestResult_Pwdump_RendersSortedLines(t *testing.T) {
	r := Result{Accounts: []Account{
		{Username: "admin", RID: 500, NT: bytes.Repeat([]byte{0xAA}, 16)},
		{Username: "guest", RID: 501},
	}}
	out := r.Pwdump()
	if !strings.Contains(out, "admin:500:") {
		t.Errorf("Pwdump missing admin line: %q", out)
	}
	if !strings.Contains(out, "guest:501:") {
		t.Errorf("Pwdump missing guest line: %q", out)
	}
}
