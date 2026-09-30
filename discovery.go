package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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
	clientCertificate, err := probeClientCertificate()
	if err != nil {
		return nil, err
	}
	var certFingerprint string
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		// LocalSend uses a self-signed certificate; compare it with its protocol identity.
		InsecureSkipVerify: true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCertificate, nil
		},
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
