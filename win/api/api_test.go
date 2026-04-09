//go:build windows

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNTSuccess(t *testing.T) {
	tests := []struct {
		name   string
		status uintptr
		want   bool
	}{
		{"STATUS_SUCCESS", 0, true},
		{"STATUS_ACCESS_DENIED", 0xC0000022, false},
		{"STATUS_INVALID_HANDLE", 0xC0000008, false},
		{"STATUS_INFO_LENGTH_MISMATCH", 0xC0000004, false},
		{"high_bit_set", 0xC0000001, false},
		{"non_zero_success_like", 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsNTSuccess(tt.status)
			assert.Equal(t, tt.want, got, "IsNTSuccess(0x%X)", tt.status)
		})
	}
}
