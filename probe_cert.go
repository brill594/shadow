package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"
)

var probeClientCertificate = sync.OnceValues(func() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	hash := sha256.Sum256(publicKey)
	serialBytes := append([]byte(nil), hash[:20]...)
	serialBytes[0] &= 0x7f
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serialBytes),
		Subject: pkix.Name{
			CommonName: "LocalSend User",
		},
		NotBefore:             time.Date(1975, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(4096, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
})
