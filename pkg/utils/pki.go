package utils

import (
	"bytes"
	"context"
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
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/tetratelabs/telemetry"
)

var (
	certCacheLock sync.Mutex
	certCache     map[string]*tls.Certificate
)

func init() {
	certCache = make(map[string]*tls.Certificate)
}

func genCertPair(ctx context.Context, settings *x509.Certificate, parent *tls.Certificate, algo string) (*tls.Certificate, error) {

	log := log.With(telemetry.KeyValuesFromContext(ctx)...)

	if len(settings.DNSNames) > 1 {
		panic(errors.New("only support one SAN atm"))
	}

	name := settings.DNSNames[0]
	log = log.With("name", name)

	certCacheLock.Lock()
	if cert, ok := certCache[name]; ok {
		x509Cert, _ := x509.ParseCertificate(cert.Certificate[0])
		log.Debug("Returning from cert cache", "serial", x509Cert.SerialNumber)
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
		log.Debug("Generating keypair", "algo", "rsa")

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
		log.Debug("Generating keypair", "algo", "ecdsa")

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
		log.Debug("Generating keypair", "algo", "ed25519")

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

	// x25519 it not applicable because it's a key-exchange protocol not a signing one

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

func GenSelfSignedCa(ctx context.Context, algo string, binName string) (*tls.Certificate, error) {

	log := log.With(telemetry.KeyValuesFromContext(ctx)...)
	log.Info("Generating CA cert")

	caSettings := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s self-signed CA", binName),
		},
		DNSNames:              []string{"ca"}, // CA cert shouldn't really have SANs, but we (horribly) use this value as the cache key
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return genCertPair(ctx, caSettings, nil, algo)
}

func GenServingCert(ctx context.Context, helloInfo *tls.ClientHelloInfo, parent *tls.Certificate, algo string, binName string) (*tls.Certificate, error) {

	log := log.With(telemetry.KeyValuesFromContext(ctx)...)
	log.Info("Generating self-signed serving cert")

	dnsName := "localhost"
	if helloInfo.ServerName != "" {
		dnsName = helloInfo.ServerName
	}

	settings := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s self-signed serving cert", binName),
		},
		DNSNames: []string{dnsName},
		// IPAddresses:    []net.IP{net.IPv4(1, 2, 3, 4)},
		// URIs: []*url.URL{&url.URL{Scheme: "spiffe", Host: "trust.domain", Path: "/ns/foo/sa/bar"}},
		// EmailAddresses: []string{"root@cia.gov"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	return genCertPair(ctx, settings, parent, algo)
}

func GenClientCert(ctx context.Context, dnsName string, parent *tls.Certificate, algo string, binName string) (*tls.Certificate, error) {

	log := log.With(telemetry.KeyValuesFromContext(ctx)...)
	log.Info("Generating self-signed client cert")

	settings := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s self-signed client cert", binName),
		},
		DNSNames: []string{dnsName},
		// IPAddresses:    []net.IP{net.IPv4(1, 2, 3, 4)},
		// URIs: []*url.URL{&url.URL{Scheme: "spiffe", Host: "trust.domain", Path: "/ns/foo/sa/bar"}},
		// EmailAddresses: []string{"root@cia.gov"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	return genCertPair(ctx, settings, parent, algo)
}
