package codec

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/mt-inside/http-log/pkg/state"
)

func ParseListener(l net.Listener, d *state.DaemonData) {
	now := time.Now()
	d.TransportListenTime = &now

	switch lis := l.(type) {
	case *net.TCPListener:
		d.TransportListenAddress = lis.Addr()
	default: // assume it's an (unexported) *tls.listener
		d.TransportListenAddress = l.Addr()
	}
}

// TODO; move to codec.tcp.go
func ParseNetConn(c net.Conn, requestNo uint64, d *state.RequestData) {
	now := time.Now()
	d.TransportConnTime = &now
	d.TransportConnNo = requestNo
	d.TransportRemoteAddress = c.RemoteAddr()
	d.TransportLocalAddress = c.LocalAddr()
}

func ParseTlsClientHello(hi *tls.ClientHelloInfo, d *state.RequestData) {
	now := time.Now()
	d.TlsNegTime = &now
	d.TlsServerName = hi.ServerName
	d.TlsNegVersions = hi.SupportedVersions
	d.TlsNegSignatureSchemes = hi.SignatureSchemes
	d.TlsNegCurves = hi.SupportedCurves
	d.TlsNegCipherSuites = hi.CipherSuites
	d.TlsNegALPN = hi.SupportedProtos
}

func ParseTlsConnectionState(cs *tls.ConnectionState, d *state.RequestData) {
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

func ParseHttpRequest(r *http.Request, srvData *state.DaemonData, d *state.RequestData) {
	now := time.Now()
	d.HttpRequestTime = &now
	d.HttpProtocolVersion = fmt.Sprintf("%d.%d", r.ProtoMajor, r.ProtoMinor)
	d.HttpMethod = r.Method

	// Store the unescaped (ie no %XX) values
	// - this means they can just be used when rendering them as strings; yes they're unescaped, but that's URL-encoding for use in HTTP; eg any '&' in query parts will still be html-element encoded
	// - if you want to parse the query you'll have to escape it again first, eg url.ParseQuery(url.EscapeQuery(foo))
	d.HttpPath = r.URL.Path                            // Store the unescaped (ie no %XX) path. FYI EscapedPath is garenteed-valid encoding of the Path, preferred over RawPath which is user-supplied and might not be a valid code
	d.HttpQuery, _ = url.QueryUnescape(r.URL.RawQuery) // Have to manually ask for this to be unescaped; the only parsing done for us is into a full Vaules structure
	//b.WarnErr(err) // TODO
	d.HttpFragment = r.URL.Fragment // Ditto EscapedFragment

	d.HttpHeaders = r.Header // Has a Clone() method but we're only gonna read
	d.HttpHost = r.Host
	d.HttpUserAgent = r.Header.Get("User-Agent")

	// Build a map (so that we don't have to call Cookies() later, and for faster lookups than that).
	// I don't believe cookie names can be duplicated
	for _, c := range r.Cookies() {
		d.HttpCookies[c.Name] = c
	}

	d.HttpContentLength = r.ContentLength
	d.HttpContentType = r.Header.Get("Content-Type")

	d.HttpHops = ExtractProxies(d, srvData)

	d.AuthJwt, d.AuthJwtErr = ExtractAndParseJWT(r, srvData.AuthJwtValidateKey)
}
