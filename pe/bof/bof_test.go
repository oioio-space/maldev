//go:build windows

package bof

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_NilData(t *testing.T) {
	b, err := Load(nil)
	assert.Nil(t, b)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}

func TestLoad_InvalidCOFF(t *testing.T) {
	// Random bytes that don't form a valid COFF.
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13}
	b, err := Load(data)
	assert.Nil(t, b)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported COFF machine type")
}

func TestLoad_TruncatedSectionTable(t *testing.T) {
	// Valid machine type but claims sections that don't fit.
	data := make([]byte, coffHeaderSize)
	// Machine = AMD64
	data[0] = 0x64
	data[1] = 0x86
	// NumberOfSections = 100 (won't fit in 20 bytes)
	data[2] = 100
	data[3] = 0

	b, err := Load(data)
	assert.Nil(t, b)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated section table")
}

func TestLoad_ValidMinimalCOFF(t *testing.T) {
	// Minimal valid COFF: AMD64 machine, 0 sections.
	data := make([]byte, coffHeaderSize)
	data[0] = 0x64
	data[1] = 0x86
	// NumberOfSections = 0
	data[2] = 0
	data[3] = 0

	b, err := Load(data)
	require.NoError(t, err)
	assert.NotNil(t, b)
	assert.Equal(t, "go", b.Entry)
}

func TestBOF_Execute_NoTextSection(t *testing.T) {
	// Valid COFF header but no .text section.
	data := make([]byte, coffHeaderSize)
	data[0] = 0x64
	data[1] = 0x86

	b := &BOF{Data: data, Entry: "go"}
	_, err := b.Execute(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), ".text section not found")
}

func TestSectionName(t *testing.T) {
	raw := [8]byte{'.', 't', 'e', 'x', 't', 0, 0, 0}
	assert.Equal(t, ".text", sectionName(raw))
}

func TestSectionName_Full(t *testing.T) {
	raw := [8]byte{'.', 'r', 'e', 'l', '.', 't', 'x', 't'}
	assert.Equal(t, ".rel.txt", sectionName(raw))
}

func TestSymbolName_Short(t *testing.T) {
	raw := [8]byte{'g', 'o', 0, 0, 0, 0, 0, 0}
	name := symbolName(raw, nil, 0)
	assert.Equal(t, "go", name)
}
