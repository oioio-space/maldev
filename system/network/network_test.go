package network

import (
	"net"
	"testing"
)

func TestGetIfacesIP(t *testing.T) {
	ips, err := GetIfacesIP()
	if err != nil {
		t.Fatal(err)
	}
	// Should have at least loopback
	if len(ips) == 0 {
		t.Fatal("expected at least one IP address")
	}
	found127 := false
	for _, ip := range ips {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			found127 = true
		}
	}
	if !found127 {
		t.Log("warning: 127.0.0.1 not in list (may be filtered)")
	}
}

func TestIsLocalLoopback(t *testing.T) {
	got, err := IsLocal("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("IsLocal(\"127.0.0.1\") = false, want true")
	}
}

func TestIsLocalLocalhost(t *testing.T) {
	got, err := IsLocal("localhost")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("IsLocal(\"localhost\") = false, want true")
	}
}

func TestIsLocalExternal(t *testing.T) {
	got, err := IsLocal("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Error("IsLocal(\"8.8.8.8\") = true, want false")
	}
}

func TestIsLocalNetIP(t *testing.T) {
	loopback := net.ParseIP("127.0.0.1")
	got, err := IsLocal(loopback)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("IsLocal(net.IP 127.0.0.1) = false, want true")
	}
}

func TestIsLocalInvalidType(t *testing.T) {
	_, err := IsLocal(12345)
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
}
