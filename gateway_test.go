package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
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
