package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	leaseFile       = "/tmp/dhcp.leases"
	ruleDirectory   = "/usr/share/nftables.d"
	liveRuleFile    = "/tmp/lan-service-gateway.apply"
	autoPeerMaxIdle = 3 * time.Minute
)

type autoPeer struct {
	mapping     localSendMap
	fingerprint string
	mac         string
	verified    time.Time
	announced   time.Time
}

func readLeases(path string) map[netip.Addr]string {
	leases := make(map[netip.Addr]string)
	f, err := os.Open(path)
	if err != nil {
		return leases
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 3 {
			continue
		}
		ip, err := netip.ParseAddr(fields[2])
		if err == nil && ip.Is4() {
			leases[ip] = strings.ToLower(fields[1])
		}
	}
	return leases
}

func announcementIdentity(data []byte) (uint16, string, bool) {
	if len(data) > 2048 {
		return 0, "", false
	}
	var message struct {
		Port        int    `json:"port"`
		Protocol    string `json:"protocol"`
		Fingerprint string `json:"fingerprint"`
		Announce    bool   `json:"announce"`
	}
	if json.Unmarshal(data, &message) != nil || !message.Announce || message.Protocol != "https" ||
		message.Port < 1 || message.Port > 65535 || message.Fingerprint == "" {
		return 0, "", false
	}
	return uint16(message.Port), message.Fingerprint, true
}

func setAnnouncementPort(data []byte, port uint16) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	fields["port"], _ = json.Marshal(port)
	return json.Marshal(fields)
}

func autoPort(c config, peers map[netip.Addr]autoPeer, wanIP netip.Addr, available func(netip.Addr, uint16) bool) (uint16, error) {
	used := make(map[uint16]bool)
	for _, m := range c.localSend {
		used[m.proxyPort] = true
	}
	if c.sunshine != nil {
		for _, port := range c.sunshine.tcpPorts {
			used[port] = true
		}
	}
	for _, peer := range peers {
		used[peer.mapping.proxyPort] = true
	}
	for port := int(c.autoStart); port <= int(c.autoEnd); port++ {
		p := uint16(port)
		if !used[p] && available(wanIP, p) {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free automatic LocalSend proxy port")
}

func tcpPortAvailable(ip netip.Addr, port uint16) bool {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(ip.AsSlice()), Port: int(port)})
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

func mergedConfig(base config, peers map[netip.Addr]autoPeer) config {
	merged := base
	merged.localSend = append([]localSendMap(nil), base.localSend...)
	addresses := make([]netip.Addr, 0, len(peers))
	for ip := range peers {
		addresses = append(addresses, ip)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	for _, ip := range addresses {
		merged.localSend = append(merged.localSend, peers[ip].mapping)
	}
	return merged
}

func applyAutoRules(base config, lan, wan interfaceState, previous, next map[netip.Addr]autoPeer) error {
	write := func(peers map[netip.Addr]autoPeer) error {
		nat, forward, err := renderRules(mergedConfig(base, peers), lan, wan)
		if err != nil {
			return err
		}
		return writeRules(ruleDirectory, liveRuleFile, nat, forward)
	}
	if err := write(next); err != nil {
		_ = write(previous)
		return err
	}
	if output, err := exec.Command("fw4", "check").CombinedOutput(); err != nil {
		_ = write(previous)
		return fmt.Errorf("fw4 check: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := exec.Command("nft", "-f", liveRuleFile).CombinedOutput(); err != nil {
		_ = write(previous)
		return fmt.Errorf("nft update: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func clonePeers(peers map[netip.Addr]autoPeer) map[netip.Addr]autoPeer {
	copy := make(map[netip.Addr]autoPeer, len(peers))
	for ip, peer := range peers {
		copy[ip] = peer
	}
	return copy
}
