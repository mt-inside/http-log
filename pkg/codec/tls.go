package codec

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func ParsePublicKey(key []byte) (crypto.PublicKey, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("file does not contain PEM-encoded data")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	return parsedKey, nil
}

func ParseCertificateRequest(bytes []byte) (*x509.CertificateRequest, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		return nil, errors.New("file does not contain PEM-encoded data")
	}

	if cert, err := x509.ParseCertificateRequest(block.Bytes); err == nil {
		return cert, nil
	}
	return nil, err
}

func ParseCertificate(bytes []byte) (*x509.Certificate, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		return nil, errors.New("file does not contain PEM-encoded data")
	}

	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert, nil
	}
	return nil, err
}

func ParseCertificates(bytes []byte) ([]*x509.Certificate, error) {
	rest := bytes
	var certs []*x509.Certificate
	var block *pem.Block
	for len(rest) != 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("file contains non PEM data")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func HeadFromCertificate(cert *tls.Certificate) *x509.Certificate {
	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		// Assume that if we have the bytes in a tls.Certificate struct that they parse, might not be true
		panic(fmt.Errorf("cert doesn't parse: %w", err))
	}
	return c
}

func ChainFromCertificate(tlsCert *tls.Certificate) (x509Certs []*x509.Certificate) {
	for _, tlsBytes := range tlsCert.Certificate {
		x509Cert, err := x509.ParseCertificate(tlsBytes)
		if err != nil {
			// Assume that if we have the bytes in a tls.Certificate struct that they parse, might not be true
			panic(fmt.Errorf("cert doesn't parse: %w", err))
		}
		x509Certs = append(x509Certs, x509Cert)
	}
	return
}
