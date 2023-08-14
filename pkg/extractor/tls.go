package extractor

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/mt-inside/http-log/pkg/state"
)

func TlsClientHello(hi *tls.ClientHelloInfo, d *state.RequestData) {
	d.TlsNegTime = time.Now()
	d.TlsServerName = hi.ServerName
	d.TlsNegVersions = hi.SupportedVersions
	d.TlsNegSignatureSchemes = hi.SignatureSchemes
	d.TlsNegCurves = hi.SupportedCurves
	d.TlsNegCipherSuites = hi.CipherSuites
	d.TlsNegALPN = hi.SupportedProtos
}

func TlsConnectionState(cs *tls.ConnectionState, d *state.RequestData) {
	d.TlsAgreedTime = time.Now()
	if cs.ServerName != d.TlsServerName {
		// This is here (extractors are normally dumb), but if this ever goes off an assumption is broken (that stdlib will abort for us), then we'll save cs.ServerName, check & warn in the renderer
		panic(fmt.Errorf("established TLS connection's ServerName '%s' != ClientHello's '%s'", cs.ServerName, d.TlsServerName))
	}
	d.TlsClientCerts = cs.PeerCertificates
	d.TlsAgreedVersion = cs.Version
	d.TlsAgreedCipherSuite = cs.CipherSuite
	d.TlsAgreedALPN = cs.NegotiatedProtocol
}
