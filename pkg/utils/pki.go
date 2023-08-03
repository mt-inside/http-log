package utils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

var (
	certCacheLock sync.Mutex
	certCache     map[string]*tls.Certificate
)

func init() {
	certCache = make(map[string]*tls.Certificate)
}

func GenCertPair(log logr.Logger, settings *x509.Certificate, parent *tls.Certificate, algo string) (*tls.Certificate, error) {

	log = log.WithName("GenCertPair")

	if len(settings.DNSNames) > 1 {
		panic(errors.New("only support one SAN atm"))
	}

	name := settings.DNSNames[0]
	log = log.WithValues("name", name)

	certCacheLock.Lock()
	if cert, ok := certCache[name]; ok {
		x509Cert, _ := x509.ParseCertificate(cert.Certificate[0])
		log.V(1).Info("Returning from cert cache", "serial", x509Cert.SerialNumber)
		certCacheLock.Unlock()
		return cert, nil
	}
	certCacheLock.Unlock()

	settings.SerialNumber = big.NewInt(time.Now().Unix())

	var signerSettings *x509.Certificate
	var signerKey crypto.PrivateKey
	if parent != nil {
		signerSettings, _ = x509.ParseCertificate(parent.Certificate[0]) // annoyingly the call to x509.CreateCertificate() gives us []byte, not a typed object, so that's what ends up in the tls.Certificate we have in hand here. That does have a typed .Leaf, but it's lazy-generated
		signerKey = parent.PrivateKey
	}

	keyPem := new(bytes.Buffer)
	var certBytes []byte

	switch algo {
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}

		err = pem.Encode(keyPem, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key), // TODO: pkcs8 prolly better, remove the RSA from the pem block when you do it
		})
		if err != nil {
			return nil, err
		}

		// Self-signing?
		if parent == nil {
			signerKey = key
			signerSettings = settings
		}

		certBytes, err = x509.CreateCertificate(rand.Reader, settings, signerSettings, &key.PublicKey, signerKey)
		if err != nil {
			return nil, err
		}

	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		keyBytes, _ := x509.MarshalECPrivateKey(key)
		err = pem.Encode(keyPem, &pem.Block{
			Type:  "ECDSA PRIVATE KEY", // TODO: this is "EC PRIVATE KEY" i belive. Should prolly use pkcs8 anyway
			Bytes: keyBytes,
		})
		if err != nil {
			return nil, err
		}

		// Self-signing?
		if parent == nil {
			signerKey = key
			signerSettings = settings
		}

		certBytes, err = x509.CreateCertificate(rand.Reader, settings, signerSettings, &key.PublicKey, signerKey)
		if err != nil {
			return nil, err
		}

	case "ed25519":
		pubKey, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
		err = pem.Encode(keyPem, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})
		if err != nil {
			return nil, err
		}

		// Self-signing?
		if parent == nil {
			signerKey = key
			signerSettings = settings
		}

		certBytes, err = x509.CreateCertificate(rand.Reader, settings, signerSettings, pubKey, signerKey)
		if err != nil {
			return nil, err
		}

	default:
		panic(errors.New("bottom"))
	}

	certPem := new(bytes.Buffer)
	err := pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}

	pair, err := tls.X509KeyPair(certPem.Bytes(), keyPem.Bytes())

	// append parent and its ancestory chain
	if parent != nil {
		pair.Certificate = append(pair.Certificate, parent.Certificate...)
	}

	certCacheLock.Lock()
	certCache[name] = &pair
	certCacheLock.Unlock()

	return &pair, err
}

func GenSelfSignedCa(log logr.Logger, algo string) (*tls.Certificate, error) {

	caSettings := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "http-log self-signed CA",
		},
		DNSNames:              []string{"ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return GenCertPair(log, caSettings, nil, algo)
}

func GenServingCert(log logr.Logger, helloInfo *tls.ClientHelloInfo, parent *tls.Certificate, algo string) (*tls.Certificate, error) {

	log.V(1).Info("TLS: get serving cert callback")

	dnsName := "localhost"
	if helloInfo.ServerName != "" {
		dnsName = helloInfo.ServerName
	}

	servingSettings := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "http-log",
		},
		DNSNames: []string{dnsName},
		// IPAddresses:    []net.IP{net.IPv4(1, 2, 3, 4)},
		// URIs: []*url.URL{&url.URL{Scheme: "spiffe", Host: "trust.domain", Path: "/ns/foo/sa/bar"}},
		// EmailAddresses: []string{"root@cia.gov"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	return GenCertPair(log, servingSettings, parent, algo)
}
