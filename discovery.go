package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var multicast = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 167), Port: 53317}

func rewriteAnnouncement(data []byte, m localSendMap) ([]byte, bool) {
	var fields map[string]json.RawMessage
	if len(data) > 2048 || json.Unmarshal(data, &fields) != nil {
		return nil, false
	}
	var port int
	var fingerprint string
	var announce bool
	if json.Unmarshal(fields["port"], &port) != nil || port != int(m.port) ||
		json.Unmarshal(fields["fingerprint"], &fingerprint) != nil || fingerprint == "" ||
		json.Unmarshal(fields["announce"], &announce) != nil || !announce {
		return nil, false
	}
	if m.fingerprint != "" && !strings.EqualFold(fingerprint, m.fingerprint) {
		return nil, false
	}
	fields["port"], _ = json.Marshal(m.proxyPort)
	out, err := json.Marshal(fields)
	return out, err == nil
}

func probeAnnouncement(m localSendMap) ([]byte, error) {
	var certFingerprint string
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		// LocalSend uses a self-signed certificate; compare it with its protocol identity.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("missing LocalSend certificate")
			}
			hash := sha256.Sum256(state.PeerCertificates[0].Raw)
			certFingerprint = strings.ToUpper(hex.EncodeToString(hash[:]))
			if m.fingerprint != "" && !strings.EqualFold(m.fingerprint, certFingerprint) {
				return fmt.Errorf("LocalSend certificate does not match configured fingerprint")
			}
			return nil
		},
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	url := fmt.Sprintf("https://%s:%d/api/localsend/v2/info", m.ip, m.port)
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LocalSend info returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 2049))
	if err != nil || len(data) > 2048 {
		return nil, fmt.Errorf("LocalSend info is too large or unreadable")
	}
	var info map[string]json.RawMessage
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	var advertisedFingerprint string
	if json.Unmarshal(info["fingerprint"], &advertisedFingerprint) != nil || !strings.EqualFold(advertisedFingerprint, certFingerprint) {
		return nil, fmt.Errorf("LocalSend info identity does not match TLS certificate")
	}
	info["port"], _ = json.Marshal(m.port)
	info["protocol"] = json.RawMessage(`"https"`)
	info["announce"] = json.RawMessage(`true`)
	data, err = json.Marshal(info)
	if err != nil {
		return nil, err
	}
	payload, ok := rewriteAnnouncement(data, m)
	if !ok {
		return nil, fmt.Errorf("LocalSend info cannot form an announcement")
	}
	return payload, nil
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

	cache := make(map[netip.Addr][]byte)
	var mu sync.RWMutex
	for _, m := range c.localSend {
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

	errors := make(chan error, 2)
	go func() {
		buf := make([]byte, 2049)
		for {
			n, sender, err := lanIn.ReadFromUDP(buf)
			if err != nil {
				errors <- fmt.Errorf("LAN multicast read: %w", err)
				return
			}
			ip, ok := netip.AddrFromSlice(sender.IP.To4())
			if !ok {
				continue
			}
			for _, m := range c.localSend {
				if m.ip != ip {
					continue
				}
				payload, ok := rewriteAnnouncement(buf[:n], m)
				if !ok {
					continue
				}
				mu.Lock()
				cache[ip] = payload
				mu.Unlock()
				if _, err := wanOut.Write(payload); err != nil {
					log.Printf("WAN multicast send: %v", err)
				}
			}
		}
	}()
	go func() {
		buf := make([]byte, 2049)
		var lastReplay time.Time
		for {
			n, sender, err := wanIn.ReadFromUDP(buf)
			if err != nil {
				errors <- fmt.Errorf("WAN multicast read: %w", err)
				return
			}
			ip, ok := netip.AddrFromSlice(sender.IP.To4())
			if !ok || ip == wan.ip || time.Since(lastReplay) < 5*time.Second {
				continue
			}
			var message struct {
				Announce bool `json:"announce"`
			}
			if json.Unmarshal(buf[:n], &message) != nil || !message.Announce {
				continue
			}
			lastReplay = time.Now()
			mu.RLock()
			for _, payload := range cache {
				if _, err := wanOut.Write(payload); err != nil {
					log.Printf("WAN multicast replay: %v", err)
				}
			}
			mu.RUnlock()
		}
	}()
	return <-errors
}
