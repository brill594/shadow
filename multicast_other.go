//go:build !linux

package main

import (
	"fmt"
	"net"
)

func openMulticast(interfaceState) (*net.UDPConn, *net.UDPConn, error) {
	return nil, nil, fmt.Errorf("multicast gateway requires Linux")
}
