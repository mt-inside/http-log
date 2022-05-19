package state

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// This layer exists so that different op "stages" can use info from other ones, eg printing HSTS header info with TLS stuff
// TODO: However the reason it splits everything out like this is to provide compatibility with other server frameworks like lambda, CF workers, etc. This might prove to be a step too far to be useful, and maybe they all wanna have different outputters (in cmd/internal?) just sharing the stylers/biosen
type RequestData struct {
	TransportConnTime      *time.Time
	TransportConnNo        uint // TODO. Where should this state be held?
	TransportRemoteAddress net.Addr
	TransportLocalAddress  net.Addr // Note that this is not the same as the Server's TcpListenAddress, as that might be eg 0.0.0.0

	TlsNegTime             *time.Time
	TlsNegServerCert       *tls.Certificate
	TlsNegVersions         []uint16
	TlsNegSignatureSchemes []tls.SignatureScheme
	TlsNegCurves           []tls.CurveID
	TlsNegCipherSuites     []uint16
	TlsNegALPN             []string

	TlsServerName  string
	TlsClientCerts []*x509.Certificate

	TlsAgreedTime        *time.Time
	TlsAgreedVersion     uint16
	TlsAgreedCipherSuite uint16
	TlsAgreedALPN        string

	HttpRequestTime     *time.Time
	HttpProtocolVersion string
	HttpMethod          string

	// All unescaped, ie have had the %XX used on the wire replaced with real characters
	HttpPath     string
	HttpQuery    string
	HttpFragment string

	HttpHeaders   http.Header
	HttpHost      string
	HttpUserAgent string

	HttpHops []*Hop

	AuthJwt    *jwt.Token
	AuthJwtErr error

	HttpContentLength   int64
	HttpContentType     string
	HttpRequestBody     []byte
	HttpRequestBodyTime *time.Time // When the body finished being read

	HttpResponseCode int
}

func NewRequestData() *RequestData {
	return &RequestData{}
}

// Hop describes a forwarding / receiving agent and the connection into it.
// Note that it makes sense to model ourselves and every proxy that's been on route, but not the original client
// - it doesn't have a connection going into it
// - its `host` address is the `client` of the first Hop
// - its `agent` is the user-agent header (should be preserved by all intermediaries)
type Hop struct {
	ClientHost  string // The address of the client connecting to it (should match `host` of the previous Hop)
	ClientPort  string // The (calling) port of the client (won't match `HostPort`)
	ClientAgent string // The agent software

	TLS     bool   // TLS status of the incoming connection
	Version string // HTTP version of the incoming connection
	VHost   string // HTTP Host header of the incoming connection

	ServerHost  string // The address/name of the agent itself
	ServerPort  string // The port of the agent
	ServerAgent string // The agent software
}
