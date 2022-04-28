package output

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

// LogRenderer is an output implementation that logs using zapr
type LogRenderer struct {
	log logr.Logger
}

// NewLogRenderer returns a new outputter than logs using zapr
func NewLogRenderer(log logr.Logger) LogRenderer {
	return LogRenderer{log}
}

func (o LogRenderer) Listen(addr net.Addr) {
	log := o.log.WithName("TCP")
	log.Info("Listening", "addr", addr)
}

func (o LogRenderer) KeySummary(key crypto.PublicKey, keyUse string) {
	log := o.log.WithName("TLS")
	log.Info("Public Key", "use", keyUse, "summary", PublicKeyInfo(key))
}
func (o LogRenderer) CertSummary(cert *x509.Certificate, certUse string) {
	log := o.log.WithName("TLS")
	// TODO: need that logStyler
	log.Info("Serving Cert", "use", certUse, "summary", "TODO")
}

// Connection announces the accepted connection
func (o LogRenderer) Connection(requestNo uint, c net.Conn) {
	log := o.log.WithName("TCP")
	log.Info("Connection", "count", requestNo, "remote", c.RemoteAddr())
}

// TLSNegSummary summarises the TLS negotiation
func (o LogRenderer) TLSNegSummary(hi *tls.ClientHelloInfo) {
	log := o.log.WithName("TLS")
	log.Info("Negotiation", "sni", hi.ServerName)
}

// TLSNegFull prints full details on the TLS negotiation
func (o LogRenderer) TLSNegFull(hi *tls.ClientHelloInfo) {
	o.TLSNegSummary(hi)

	log := o.log.WithName("TLS")
	log.Info("Supported", "versions", TLSVersions2Strings(hi.SupportedVersions))
	log.Info("Supported", "cert types", Slice2Strings(hi.SignatureSchemes))
	log.Info("Supported", "cert curves", Slice2Strings(hi.SupportedCurves))
	log.Info("Supported", "symmetric cypher suites", CipherSuites2Strings(hi.CipherSuites))
	log.Info("Supported", "ALPN protocols", hi.SupportedProtos)
}

// TLSSummary summarises the connection transport
func (o LogRenderer) TLSSummary(cs *tls.ConnectionState, clientCa *x509.Certificate) {
	log := o.log.WithName("TLS")
	log.Info(
		"Agreed",
		"sni", cs.ServerName,
		"version", TLSVersionName(cs.Version),
		"alpn", cs.NegotiatedProtocol,
	)

	// TODO log one-line clientcert summary (is now when we need a logStyler?)
}

// TLSFull prints full details on the connection transport
func (o LogRenderer) TLSFull(cs *tls.ConnectionState, clientCa *x509.Certificate) {
	o.TLSSummary(cs, clientCa)

	log := o.log.WithName("TLS")
	log.Info("Agreed", "symmetric cipher suite", cs.CipherSuite)

	// TODO log full client cert chain
}

// HeadSummary summarises the application-layer request header
func (o LogRenderer) HeadSummary(proto, method, host, ua string, url *url.URL, respCode int) {
	log := o.log.WithName("HTTP")
	log.Info(
		"Request",
		"proto", proto,
		"method", method,
		"host", host,
		"path", url.RequestURI(),
		"user-agent", ua,
		"response", respCode,
	)
}

// HeadFull prints full contents of the application-layer request header
func (o LogRenderer) HeadFull(r *http.Request, respCode int) {
	log := o.log.WithName("HTTP")
	log.Info("Request", "proto", r.Proto)
	log.Info("Request", "method", r.Method)
	// TODO: break this out into path, all query components, all fragment components (like tty HeadFULL)
	log.Info("Request", "uri", r.URL.RequestURI())
	log.Info("Request", "host", r.Host)
	for k, v := range r.Header {
		log.Info("Header", "name", k, "values", v)
	}
	log.Info("Response", "status", respCode)
}

// JWTSummary summarises the JWT in the request
func (o LogRenderer) JWTSummary(tokenErr error, start, end *time.Time, ID, subject, issuer string, audience []string) {
	log := o.log.WithName("Auth").WithName("JWT")

	log.Info(
		"Claims",
		"start", start.Format(time.RFC3339),
		"end", end.Format(time.RFC3339),
		"id", ID,
		"sub", subject,
		"iss", issuer,
		"aud", strings.Join(audience, ","),
	)
}

// JWTFull prints detailed information about the JWT in the request
func (o LogRenderer) JWTFull(tokenErr error, start, end *time.Time, ID, subject, issuer string, audience []string, sigAlgo, hashAlgo string) {
	o.JWTSummary(tokenErr, start, end, ID, subject, issuer, audience)

	log := o.log.WithName("Auth").WithName("JWT")

	log.Info(
		"Signature",
		"algo", sigAlgo,
		"hash", hashAlgo,
	)
}

// BodySummary summarises the application-layer request body
func (o LogRenderer) BodySummary(contentType string, contentLength int64, bs []byte) {
	log := o.log.WithName("HTTP")
	bodyLen := len(bs)
	printLen := Min(bodyLen, 72)

	log.Info("Body",
		"len", contentLength,
		"type", contentType,
		"content", string(bs[0:printLen]),
		"elided", bodyLen-printLen,
	)
}

// BodyFull prints full contents of the application-layer request body
func (o LogRenderer) BodyFull(contentType string, contentLength int64, bs []byte) {
	log := o.log.WithName("HTTP")
	log.Info("Body",
		"len", contentLength,
		"type", contentType,
		"content", string(bs),
	)
}
