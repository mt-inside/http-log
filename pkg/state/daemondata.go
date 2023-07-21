package state

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

type TransportListen struct {
	Time    time.Time
	Address net.Addr
}

type DaemonData struct {
	TransportListen []TransportListen

	TlsOn              bool // tcp-socket only; h3 is always TLS
	TlsServingSelfSign bool
	TlsServingCertPair *tls.Certificate // TODO why u a pointer?
	TlsClientCA        *x509.Certificate

	AuthJwtValidateKey crypto.PublicKey
}

func NewDaemonData() *DaemonData {
	return &DaemonData{}
}

func (dd *DaemonData) ServingProtocol() string {
	if dd.TlsOn {
		return "https"
	} else {
		return "http"
	}
}
