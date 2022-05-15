package state

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

type DaemonData struct {
	TransportListenTime    *time.Time
	TransportListenAddress net.Addr

	TlsOn              bool
	TlsServingSelfSign bool
	TlsServingCertPair *tls.Certificate // TODO why u a pointer?
	TlsClientCA        *x509.Certificate

	AuthJwtValidateKey crypto.PublicKey
}

func NewDaemonData() *DaemonData {
	return &DaemonData{}
}
