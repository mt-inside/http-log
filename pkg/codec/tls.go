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

func ParseCertificate(cert []byte) (*x509.Certificate, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(cert); block == nil {
		return nil, errors.New("file does not contain PEM-encoded data")
	}

	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert, nil
	}
	return nil, err
}

func HeadFromCertificate(cert *tls.Certificate) *x509.Certificate {
	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		// Assume that if we have the bytes in a tls.Certificate struct that they parse, might not be true
		// NB: can't use output.Bios in this package; it doesn't output
		panic(fmt.Errorf("cert doesn't parse: %w", err))
	}
	return c
}

func ChainFromCertificate(tlsCert *tls.Certificate) (x509Certs []*x509.Certificate) {
	for _, tlsBytes := range tlsCert.Certificate {
		x509Cert, err := x509.ParseCertificate(tlsBytes)
		if err != nil {
			// Assume that if we have the bytes in a tls.Certificate struct that they parse, might not be true
			// NB: can't use output.Bios in this package; it doesn't output
			panic(fmt.Errorf("cert doesn't parse: %w", err))
		}
		x509Certs = append(x509Certs, x509Cert)
	}
	return
}
