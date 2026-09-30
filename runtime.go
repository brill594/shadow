package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"
)

type multicastEvent struct {
	side string
	ip   netip.Addr
	data []byte
}

type probeResult struct {
	ip      netip.Addr
	port    uint16
	payload []byte
	err     error
}

type probeRequest struct {
	port        uint16
	fingerprint string
}

func readMulticast(side string, conn *net.UDPConn, events chan<- multicastEvent, errors chan<- error) {
	buf := make([]byte, 2049)
	for {
		n, sender, err := conn.ReadFromUDP(buf)
		if err != nil {
			errors <- fmt.Errorf("%s multicast read: %w", side, err)
			return
		}
		ip, ok := netip.AddrFromSlice(sender.IP.To4())
		if !ok {
			continue
		}
		packet := multicastEvent{side, ip, append([]byte(nil), buf[:n]...)}
		select {
		case events <- packet:
		default:
			log.Printf("%s multicast queue full; dropping packet", side)
		}
	}
}

func verifiedReplay(peer autoPeer, port uint16, fingerprint string, now time.Time) bool {
	return peer.mapping.port == port && strings.EqualFold(peer.fingerprint, fingerprint) &&
		now.Sub(peer.verified) <= autoPeerMaxIdle
}

func runDiscovery(c config, lan, wan interfaceState) error {
	if err := c.validateNetworks(lan, wan); err != nil {
		return err
	}
	lanIn, lanOut, err := openMulticast(lan)
	if err != nil {
		return fmt.Errorf("LAN multicast: %w", err)
	}
	defer lanIn.Close()
	lanOut.Close()
	wanIn, wanOut, err := openMulticast(wan)
	if err != nil {
		return fmt.Errorf("WAN multicast: %w", err)
	}
	defer wanIn.Close()
	defer wanOut.Close()

	peers := make(map[netip.Addr]autoPeer)
	if c.auto {
		if err := applyAutoRules(c, lan, wan, peers, peers); err != nil {
			return fmt.Errorf("reset automatic mappings: %w", err)
		}
	}
	cache := make(map[netip.Addr][]byte)
	static := make(map[netip.Addr]localSendMap)
	for _, m := range c.localSend {
		static[m.ip] = m
		payload, err := probeAnnouncement(m)
		if err != nil {
			log.Printf("LocalSend probe %s: %v", m.ip, err)
			continue
		}
		cache[m.ip] = payload
		if _, err := wanOut.Write(payload); err != nil {
			log.Printf("WAN multicast send: %v", err)
		}
	}

	events := make(chan multicastEvent, 64)
	errors := make(chan error, 2)
	results := make(chan probeResult, 32)
	slots := make(chan struct{}, 8)
	pending := make(map[netip.Addr]probeRequest)
	retry := make(map[netip.Addr]probeRequest)
	go readMulticast("lan", lanIn, events, errors)
	go readMulticast("wan", wanIn, events, errors)

	queueProbe := func(ip netip.Addr, port uint16, fingerprint string) {
		if !c.auto || !lan.subnet.Contains(ip) || ip == lan.ip {
			return
		}
		if active, busy := pending[ip]; busy {
			if active.port != port || (fingerprint != "" && !strings.EqualFold(active.fingerprint, fingerprint)) {
				retry[ip] = probeRequest{port, fingerprint}
			}
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			return
		}
		pending[ip] = probeRequest{port, fingerprint}
		go func() {
			defer func() { <-slots }()
			payload, err := probeAnnouncement(localSendMap{ip: ip, port: port, fingerprint: fingerprint})
			results <- probeResult{ip: ip, port: port, payload: payload, err: err}
		}()
	}

	scan := func() {
		if !c.auto {
			return
		}
		leases := readLeases(leaseFile)
		now := time.Now()
		next := clonePeers(peers)
		for ip, peer := range peers {
			mac, leased := leases[ip]
			if (leased && peer.mac != "" && mac != peer.mac) || now.Sub(peer.verified) > autoPeerMaxIdle {
				delete(next, ip)
			}
		}
		if len(next) != len(peers) {
			if err := applyAutoRules(c, lan, wan, peers, next); err != nil {
				log.Printf("remove stale LocalSend mapping: %v", err)
			} else {
				for ip := range peers {
					if _, keep := next[ip]; !keep {
						delete(cache, ip)
						log.Printf("auto LocalSend %s mapping expired", ip)
					}
				}
				peers = next
			}
		}
		for ip := range leases {
			if _, fixed := static[ip]; fixed || !lan.subnet.Contains(ip) || ip == lan.ip {
				continue
			}
			if peer, exists := peers[ip]; exists {
				if peer.mac == "" || peer.mac == leases[ip] {
					queueProbe(ip, peer.mapping.port, peer.fingerprint)
				}
			} else {
				queueProbe(ip, 53317, "")
			}
		}
		for ip, peer := range peers {
			if _, leased := leases[ip]; !leased {
				queueProbe(ip, peer.mapping.port, peer.fingerprint)
			}
		}
	}
	scan()
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	var lastReplay time.Time
	for {
		select {
		case event := <-events:
			if event.side == "lan" {
				if m, fixed := static[event.ip]; fixed {
					payload, ok := rewriteAnnouncement(event.data, m)
					if ok {
						cache[event.ip] = payload
						if _, err := wanOut.Write(payload); err != nil {
							log.Printf("WAN multicast send: %v", err)
						}
					}
					continue
				}
				if port, fingerprint, ok := announcementIdentity(event.data); ok {
					if peer, known := peers[event.ip]; known && verifiedReplay(peer, port, fingerprint, time.Now()) {
						if payload := cache[event.ip]; len(payload) != 0 {
							if _, err := wanOut.Write(payload); err != nil {
								log.Printf("WAN multicast send: %v", err)
							}
							peer.announced = time.Now()
							peers[event.ip] = peer
						}
					}
					queueProbe(event.ip, port, fingerprint)
				}
				continue
			}
			if event.ip == wan.ip || time.Since(lastReplay) < 5*time.Second {
				continue
			}
			var message struct {
				Announce bool `json:"announce"`
			}
			if json.Unmarshal(event.data, &message) != nil || !message.Announce {
				continue
			}
			lastReplay = time.Now()
			for _, payload := range cache {
				if _, err := wanOut.Write(payload); err != nil {
					log.Printf("WAN multicast replay: %v", err)
				}
			}
		case result := <-results:
			delete(pending, result.ip)
			if later, queued := retry[result.ip]; queued {
				delete(retry, result.ip)
				queueProbe(result.ip, later.port, later.fingerprint)
			}
			if result.err != nil {
				continue
			}
			var info struct {
				Fingerprint string `json:"fingerprint"`
			}
			if json.Unmarshal(result.payload, &info) != nil || info.Fingerprint == "" {
				continue
			}
			previous, exists := peers[result.ip]
			proxy := previous.mapping.proxyPort
			if !exists {
				var err error
				proxy, err = autoPort(c, peers, wan.ip, tcpPortAvailable)
				if err != nil {
					log.Printf("auto LocalSend %s: %v", result.ip, err)
					continue
				}
			}
			payload, err := setAnnouncementPort(result.payload, proxy)
			if err != nil {
				continue
			}
			mac := readLeases(leaseFile)[result.ip]
			now := time.Now()
			peer := autoPeer{
				mapping:     localSendMap{ip: result.ip, port: result.port, proxyPort: proxy, fingerprint: info.Fingerprint},
				fingerprint: info.Fingerprint,
				mac:         mac,
				verified:    now,
				announced:   previous.announced,
			}
			changed := !exists || previous.mapping.port != peer.mapping.port ||
				!strings.EqualFold(previous.fingerprint, peer.fingerprint) || previous.mac != mac
			if changed {
				next := clonePeers(peers)
				next[result.ip] = peer
				if err := applyAutoRules(c, lan, wan, peers, next); err != nil {
					log.Printf("auto LocalSend %s rule update: %v", result.ip, err)
					continue
				}
				peers = next
				log.Printf("auto LocalSend %s mapped to upstream TCP port %d", result.ip, proxy)
			}
			cache[result.ip] = payload
			if changed || now.Sub(previous.announced) > 2*time.Minute {
				peer.announced = now
				if _, err := wanOut.Write(payload); err != nil {
					log.Printf("WAN multicast send: %v", err)
				}
			}
			peers[result.ip] = peer
		case <-ticker.C:
			scan()
		case err := <-errors:
			return err
		}
	}
}
