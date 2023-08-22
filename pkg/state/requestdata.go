package state

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// This layer exists so that different op "stages" can use info from other ones, eg printing HSTS header info with TLS stuff
// TODO: However the reason it splits everything out like this is to provide compatibility with other server frameworks like lambda, CF workers, etc. This might prove to be a step too far to be useful, and maybe they all wanna have different outputters (in cmd/internal?) just sharing the stylers/biosen
type RequestData struct {
	TransportConnTime             time.Time
	TransportConnNo               uint64 // TODO. Where should this state be held?
	TransportRemoteAddress        net.Addr
	TransportLocalAddress         net.Addr // Note that this is not the same as the Server's TcpListenAddress, as that might be eg 0.0.0.0
	TransportProxyProtocol        bool
	TransportProxyProtocolVersion byte

	TlsNegTime             time.Time
	TlsNegServerCert       *tls.Certificate
	TlsNegVersions         []uint16
	TlsNegSignatureSchemes []tls.SignatureScheme
	TlsNegCurves           []tls.CurveID
	TlsNegCipherSuites     []uint16
	TlsNegALPN             []string

	TlsServerName  string
	TlsClientCerts []*x509.Certificate

	TlsAgreedTime        time.Time
	TlsAgreedVersion     uint16
	TlsAgreedCipherSuite uint16
	TlsAgreedALPN        string

	HttpRequestTime     time.Time
	HttpProtocolVersion string
	HttpMethod          string

	// All unescaped, ie have had the %XX used on the wire replaced with real characters
	HttpPath     string
	HttpQuery    string
	HttpFragment string

	HttpHeaders   http.Header
	HttpHost      string
	HttpUserAgent string

	HttpCookies map[string]*http.Cookie

	HttpHops []*Hop

	AuthJwt    *jwt.Token
	AuthJwtErr error

	AuthOIDC                     bool
	AuthOIDCDiscoSupportedClaims []string
	AuthOIDCDiscoSupportedSigs   []string
	AuthOIDCUserinfo             map[string]any
	AuthOIDCJwks                 map[string]any

	HttpBodyTime      time.Time // When the body finished being read
	HttpBodyErr       error
	HttpContentLength int64
	HttpContentType   string
	HttpBody          []byte
	HttpBodyLen       int64
}

func NewRequestData() *RequestData {
	return &RequestData{
		HttpCookies: map[string]*http.Cookie{},
	}
}
