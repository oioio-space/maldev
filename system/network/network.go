// Package network provides IP address retrieval and local address detection.
package network

import (
	"errors"
	"net"
)

// InterfaceIPs returns all IP addresses of the machine (including loopback).
func InterfaceIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	IPs := make([]net.IP, 0)

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				IPs = append(IPs, v.IP)
			case *net.IPAddr:
				IPs = append(IPs, v.IP)
			}
		}
	}

	return IPs, nil
}

// ErrNotIPorDN indicates the argument is neither an IP nor a domain name.
var ErrNotIPorDN = errors.New("not IP or domain name")

// IsLocal returns true if the given IP or domain name corresponds to the local machine.
func IsLocal(IPorDN any) (bool, error) {
	ip := make([]net.IP, 0)
	switch v := IPorDN.(type) {
	case net.IP:
		ip = append(ip, v)
	case string:
		ipTemp := net.ParseIP(v)
		if ipTemp == nil {
			var err error
			ip, err = net.LookupIP(v)
			if err != nil {
				return false, ErrNotIPorDN
			}
		} else {
			ip = append(ip, ipTemp)
		}
	default:
		return false, ErrNotIPorDN
	}

	ips, err := InterfaceIPs()
	if err != nil {
		return false, err
	}

	for _, ip1 := range ips {
		for _, ip2 := range ip {
			if ip2.Equal(ip1) {
				return true, nil
			}
		}
	}

	return false, nil
}
