package kcallback

import (
	"errors"
	"testing"
)

func TestKindString(t *testing.T) {
	cases := map[Kind]string{
		KindCreateProcess: "PspCreateProcessNotifyRoutine",
		KindCreateThread:  "PspCreateThreadNotifyRoutine",
		KindLoadImage:     "PspLoadImageNotifyRoutine",
		Kind(999):         "kcallback.Kind(unknown)",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", k, got, want)
		}
	}
}

func TestNullKernelReader_ReturnsErrNoKernelReader(t *testing.T) {
	var r NullKernelReader
	buf := make([]byte, 8)
	n, err := r.ReadKernel(0xDEADBEEF, buf)
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
	if !errors.Is(err, ErrNoKernelReader) {
		t.Errorf("err = %v, want ErrNoKernelReader", err)
	}
}
