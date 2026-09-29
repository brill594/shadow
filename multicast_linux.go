//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
)

const ipMulticastAll = 49

func openMulticast(state interfaceState) (*net.UDPConn, *net.UDPConn, error) {
	iface, err := net.InterfaceByName(state.device)
	if err != nil {
		return nil, nil, err
	}
	in, err := net.ListenMulticastUDP("udp4", iface, multicast)
	if err != nil {
		return nil, nil, err
	}
	if err := socketOption(in, func(fd int) error {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipMulticastAll, 0)
	}); err != nil {
		in.Close()
		return nil, nil, err
	}
	out, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IP(state.ip.AsSlice())}, multicast)
	if err != nil {
		in.Close()
		return nil, nil, err
	}
	err = socketOption(out, func(fd int) error {
		if err := syscall.SetsockoptInet4Addr(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, state.ip.As4()); err != nil {
			return err
		}
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 1); err != nil {
			return err
		}
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 0)
	})
	if err != nil {
		in.Close()
		out.Close()
		return nil, nil, err
	}
	return in, out, nil
}

func socketOption(conn *net.UDPConn, set func(int) error) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) { sockErr = set(int(fd)) }); err != nil {
		return err
	}
	if sockErr != nil {
		return fmt.Errorf("multicast socket option: %w", sockErr)
	}
	return nil
}
