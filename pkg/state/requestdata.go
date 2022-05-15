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
	TcpConnTime      *time.Time
	TcpConnNo        uint // TODO. Where should this state be held?
	TcpRemoteAddress net.Addr
	TcpLocalAddress  net.Addr // Note that this is not the same as the Server's TcpListenAddress, as that might be eg 0.0.0.0

	TlsNegTime             *time.Time
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
