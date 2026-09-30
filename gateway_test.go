package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnnouncementKeepsPeerIdentityWhileChangingReachablePort(t *testing.T) {
	mapToLAN := localSendMap{ip: netip.MustParseAddr("192.168.8.167"), port: 53317, proxyPort: 55001, fingerprint: "cert-id"}
	in := []byte(`{"alias":"Peer","fingerprint":"cert-id","port":53317,"protocol":"https","announce":true,"extension":{"x":1}}`)
	out, ok := rewriteAnnouncement(in, mapToLAN)
	if !ok {
		t.Fatal("valid LocalSend announcement was rejected")
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["port"] != float64(55001) || got["fingerprint"] != "cert-id" || got["protocol"] != "https" || got["alias"] != "Peer" || got["extension"] == nil {
		t.Fatalf("announcement lost peer identity or reachable port: %v", got)
	}
	for _, payload := range []string{
		`{"fingerprint":"other","port":53317,"announce":true}`,
		`{"fingerprint":"cert-id","port":53318,"announce":true}`,
		`{"fingerprint":"cert-id","port":53317,"announce":false}`,
	} {
		if _, ok := rewriteAnnouncement([]byte(payload), mapToLAN); ok {
			t.Fatalf("forwarded nonmatching or non-announcement payload: %s", payload)
		}
	}
}

func TestProbePublishesTheLiveCertificateIdentity(t *testing.T) {
	var fingerprint string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/localsend/v2/info" {
			t.Errorf("unexpected info path: %s", r.URL.Path)
		}
		fmt.Fprintf(w, `{"alias":"Peer","version":"2.1","fingerprint":%q}`, fingerprint)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	hash := sha256.Sum256(server.TLS.Certificates[0].Certificate[0])
	fingerprint = strings.ToUpper(hex.EncodeToString(hash[:]))
	port := uint16(server.Listener.Addr().(*net.TCPAddr).Port)
	m := localSendMap{ip: netip.MustParseAddr("127.0.0.1"), port: port, proxyPort: 55001, fingerprint: fingerprint}
	payload, err := probeAnnouncement(m)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Fingerprint string `json:"fingerprint"`
		Port        int    `json:"port"`
		Announce    bool   `json:"announce"`
	}
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != fingerprint || got.Port != 55001 || !got.Announce {
		t.Fatalf("probe did not preserve the live identity and proxy port: %+v", got)
	}
	fingerprint = "wrong identity"
	if _, err := probeAnnouncement(m); err == nil {
		t.Fatal("published info that disagreed with the TLS certificate")
	}
}

func TestProbeCertificateUsesLocalSendIdentityProfile(t *testing.T) {
	certificate, err := probeClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() != 2048 || parsed.Subject.CommonName != "LocalSend User" ||
		len(parsed.DNSNames) != 0 || parsed.IsCA || !parsed.NotAfter.After(time.Now().AddDate(5, 0, 0)) {
		t.Fatalf("unexpected LocalSend probe certificate profile: %s", parsed.Subject)
	}
}

func TestRulesExposeOnlyConfiguredRouterPorts(t *testing.T) {
	lan := interfaceState{"br-lan", netip.MustParseAddr("192.168.8.1"), netip.MustParsePrefix("192.168.8.0/24")}
	wan := interfaceState{"phy0.1-sta0", netip.MustParseAddr("172.16.32.22"), netip.MustParsePrefix("172.16.0.0/16")}
	c := config{localSend: []localSendMap{{ip: netip.MustParseAddr("192.168.8.167"), port: 53317, proxyPort: 55001}}, sunshine: &sunshineMap{ip: netip.MustParseAddr("192.168.8.126"), tcpPorts: []uint16{47989}, udpPorts: []uint16{47998}}}
	nat, forward, err := renderRules(c, lan, wan)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "phy0.1-sta0" ip daddr 172.16.32.22 tcp dport 55001 dnat ip to 192.168.8.167:53317`,
		`iifname "phy0.1-sta0" ip daddr 172.16.32.22 tcp dport 47989 dnat ip to 192.168.8.126:47989`,
		`iifname "phy0.1-sta0" ip daddr 172.16.32.22 udp dport 47998 dnat ip to 192.168.8.126:47998`,
	} {
		if !strings.Contains(nat, want) {
			t.Fatalf("missing constrained DNAT rule %q in %q", want, nat)
		}
	}
	if strings.Contains(nat, `iifname "br-lan"`) {
		t.Fatal("reverse LocalSend proxy would let WAN masquerade overwrite the peer's reachable port")
	}
	if strings.Count(forward, "ct status dnat accept") != 3 {
		t.Fatalf("forward rules do not require DNAT state: %s", forward)
	}
	c.localSend[0].ip = netip.MustParseAddr("172.16.32.9")
	if _, _, err := renderRules(c, lan, wan); err == nil {
		t.Fatal("accepted a LAN mapping to an upstream target")
	}
}

func TestAutomaticPeerAdmissionUsesASeparateAvailablePort(t *testing.T) {
	packet := []byte(`{"fingerprint":"cert-id","port":53317,"protocol":"https","announce":true}`)
	port, fingerprint, ok := announcementIdentity(packet)
	if !ok || port != 53317 || fingerprint != "cert-id" {
		t.Fatal("valid LocalSend announcement was not recognized")
	}
	for _, invalid := range []string{
		`{"fingerprint":"cert-id","port":53317,"protocol":"http","announce":true}`,
		`{"fingerprint":"cert-id","port":53317,"protocol":"https","announce":false}`,
	} {
		if _, _, ok := announcementIdentity([]byte(invalid)); ok {
			t.Fatalf("accepted an unsupported automatic announcement: %s", invalid)
		}
	}

	mac := netip.MustParseAddr("192.168.8.167")
	ipad := netip.MustParseAddr("192.168.8.109")
	wan := netip.MustParseAddr("172.16.32.22")
	c := config{
		auto: true, autoStart: 55100, autoEnd: 55104,
		localSend: []localSendMap{{ip: mac, port: 53317, proxyPort: 55001}},
		sunshine:  &sunshineMap{ip: netip.MustParseAddr("192.168.8.126"), tcpPorts: []uint16{55100}},
	}
	peers := map[netip.Addr]autoPeer{ipad: {mapping: localSendMap{ip: ipad, port: 53317, proxyPort: 55101}}}
	got, err := autoPort(c, peers, wan, func(_ netip.Addr, p uint16) bool { return p != 55102 })
	if err != nil || got != 55103 {
		t.Fatalf("automatic port must avoid existing services and unavailable ports: %d, %v", got, err)
	}
	merged := mergedConfig(c, peers)
	if len(merged.localSend) != 2 || len(c.localSend) != 1 {
		t.Fatal("automatic peer was not added without changing the static configuration")
	}
	lanState := interfaceState{"br-lan", netip.MustParseAddr("192.168.8.1"), netip.MustParsePrefix("192.168.8.0/24")}
	wanState := interfaceState{"phy0.1-sta0", wan, netip.MustParsePrefix("172.16.0.0/16")}
	nat, _, err := renderRules(merged, lanState, wanState)
	if err != nil || !strings.Contains(nat, "tcp dport 55101 dnat ip to 192.168.8.109:53317") {
		t.Fatalf("verified automatic peer did not receive its own narrow DNAT rule: %v, %s", err, nat)
	}
}

func TestAutomaticRangeMustBeBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.conf")
	for _, test := range []struct {
		line  string
		valid bool
	}{{"auto 55100 55999", true}, {"auto 55999 55100", false}, {"auto 1024 65535", false}} {
		if err := os.WriteFile(path, []byte("interfaces br-lan phy0.1-sta0\n"+test.line+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := readConfig(path)
		if (err == nil) != test.valid {
			t.Fatalf("range %q validity mismatch: %v", test.line, err)
		}
	}
}

func TestVerifiedRefreshReplaysWithoutWaitingForPeriodicAnnouncement(t *testing.T) {
	now := time.Now()
	peer := autoPeer{
		mapping:     localSendMap{port: 53317},
		fingerprint: "CERT-ID",
		verified:    now.Add(-30 * time.Second),
		announced:   now.Add(-time.Second),
	}
	if !verifiedReplay(peer, 53317, "cert-id", now) {
		t.Fatal("a verified peer refresh must trigger immediate upstream replay")
	}
	if verifiedReplay(peer, 53318, "cert-id", now) || verifiedReplay(peer, 53317, "other", now) {
		t.Fatal("a different endpoint or identity must not trigger replay")
	}
	peer.verified = now.Add(-autoPeerMaxIdle - time.Second)
	if verifiedReplay(peer, 53317, "cert-id", now) {
		t.Fatal("an expired automatic peer must be reverified before replay")
	}
}
