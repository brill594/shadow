package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type localSendMap struct {
	ip          netip.Addr
	port        uint16
	proxyPort   uint16
	fingerprint string
}

type sunshineMap struct {
	ip       netip.Addr
	tcpPorts []uint16
	udpPorts []uint16
}

type config struct {
	lanDevice string
	wanDevice string
	localSend []localSendMap
	sunshine  *sunshineMap
}

var deviceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]+$`)

func readConfig(path string) (config, error) {
	f, err := os.Open(path)
	if err != nil {
		return config{}, err
	}
	defer f.Close()

	var c config
	s := bufio.NewScanner(f)
	for line := 1; s.Scan(); line++ {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		bad := func() (config, error) {
			return config{}, fmt.Errorf("config line %d: invalid %s entry", line, fields[0])
		}
		switch fields[0] {
		case "interfaces":
			if len(fields) != 3 || c.lanDevice != "" || !deviceName.MatchString(fields[1]) || !deviceName.MatchString(fields[2]) || fields[1] == fields[2] {
				return bad()
			}
			c.lanDevice, c.wanDevice = fields[1], fields[2]
		case "localsend":
			if len(fields) != 5 {
				return bad()
			}
			ip, err := parseIPv4(fields[1])
			if err != nil {
				return bad()
			}
			port, err1 := parsePort(fields[2], false)
			proxy, err2 := parsePort(fields[3], true)
			if err1 != nil || err2 != nil || len(fields[4]) > 128 {
				return bad()
			}
			fingerprint := fields[4]
			if fingerprint == "-" {
				fingerprint = ""
			}
			c.localSend = append(c.localSend, localSendMap{ip, port, proxy, fingerprint})
		case "sunshine":
			if len(fields) != 4 || c.sunshine != nil {
				return bad()
			}
			ip, err := parseIPv4(fields[1])
			if err != nil {
				return bad()
			}
			tcp, err1 := parsePorts(fields[2])
			udp, err2 := parsePorts(fields[3])
			if err1 != nil || err2 != nil || len(tcp)+len(udp) == 0 {
				return bad()
			}
			c.sunshine = &sunshineMap{ip, tcp, udp}
		default:
			return bad()
		}
	}
	if err := s.Err(); err != nil {
		return config{}, err
	}
	if c.lanDevice == "" {
		return config{}, fmt.Errorf("config: missing interfaces")
	}
	return c, c.validatePorts()
}

func parseIPv4(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || !ip.Is4() || !ip.IsPrivate() {
		return netip.Addr{}, fmt.Errorf("invalid private IPv4 address %q", s)
	}
	return ip, nil
}

func parsePort(s string, proxy bool) (uint16, error) {
	n, err := strconv.Atoi(s)
	min := 1
	if proxy {
		min = 1024
	}
	if err != nil || n < min || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(n), nil
}

func parsePorts(s string) ([]uint16, error) {
	if s == "-" {
		return nil, nil
	}
	var out []uint16
	seen := map[uint16]bool{}
	for _, item := range strings.Split(s, ",") {
		p, err := parsePort(item, false)
		if err != nil || seen[p] {
			return nil, fmt.Errorf("invalid or duplicate Sunshine port %q", item)
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

func (c config) validatePorts() error {
	used := map[string]bool{}
	for _, m := range c.localSend {
		key := fmt.Sprintf("wan/tcp/%d", m.proxyPort)
		if used[key] {
			return fmt.Errorf("duplicate proxy port %s", key)
		}
		used[key] = true
	}
	if c.sunshine != nil {
		for _, pair := range []struct {
			proto string
			ports []uint16
		}{{"tcp", c.sunshine.tcpPorts}, {"udp", c.sunshine.udpPorts}} {
			for _, p := range pair.ports {
				key := fmt.Sprintf("wan/%s/%d", pair.proto, p)
				if used[key] {
					return fmt.Errorf("Sunshine port conflicts with proxy %s", key)
				}
				used[key] = true
			}
		}
	}
	return nil
}

type interfaceState struct {
	device string
	ip     netip.Addr
	subnet netip.Prefix
}

func currentInterface(name string) (interfaceState, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return interfaceState{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return interfaceState{}, err
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		ip, _ := netip.AddrFromSlice(ipnet.IP.To4())
		bits, _ := ipnet.Mask.Size()
		return interfaceState{name, ip, netip.PrefixFrom(ip, bits).Masked()}, nil
	}
	return interfaceState{}, fmt.Errorf("interface %s has no IPv4 address", name)
}

func (c config) validateNetworks(lan, wan interfaceState) error {
	for _, m := range c.localSend {
		if !lan.subnet.Contains(m.ip) || m.ip == lan.ip {
			return fmt.Errorf("LocalSend target %s is not a peer on %s", m.ip, lan.device)
		}
	}
	if c.sunshine != nil && (!lan.subnet.Contains(c.sunshine.ip) || c.sunshine.ip == lan.ip) {
		return fmt.Errorf("Sunshine target %s is not a LAN peer", c.sunshine.ip)
	}
	return nil
}
