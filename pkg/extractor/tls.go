package extractor

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/mt-inside/http-log/pkg/state"
)

func TlsClientHello(hi *tls.ClientHelloInfo, d *state.RequestData) {
	now := time.Now()
	d.TlsNegTime = &now
	d.TlsServerName = hi.ServerName
	d.TlsNegVersions = hi.SupportedVersions
	d.TlsNegSignatureSchemes = hi.SignatureSchemes
	d.TlsNegCurves = hi.SupportedCurves
	d.TlsNegCipherSuites = hi.CipherSuites
	d.TlsNegALPN = hi.SupportedProtos
}

func TlsConnectionState(cs *tls.ConnectionState, d *state.RequestData) {
	now := time.Now()
	d.TlsAgreedTime = &now
	if cs.ServerName != d.TlsServerName {
		panic(fmt.Errorf("established TLS connection's ServerName '%s' != ClientHello's '%s'", cs.ServerName, d.TlsServerName))
	}
	d.TlsClientCerts = cs.PeerCertificates
	d.TlsAgreedVersion = cs.Version
	d.TlsAgreedCipherSuite = cs.CipherSuite
	d.TlsAgreedALPN = cs.NegotiatedProtocol
}
