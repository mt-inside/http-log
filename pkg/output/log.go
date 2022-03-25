package output

import (
	"crypto/tls"
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

// TLSNegSummary summarises the TLS negotiation
func (o LogRenderer) TLSNegSummary(hi *tls.ClientHelloInfo) {
	log := o.log.WithName("Transport")
	log.Info("negotiation", "sni", hi.ServerName)
}

// TLSNegFull prints full details on the TLS negotiation
func (o LogRenderer) TLSNegFull(hi *tls.ClientHelloInfo) {
	o.TLSNegSummary(hi)

	log := o.log.WithName("Transport")
	log.Info("supported", "versions", TLSVersions2Strings(hi.SupportedVersions))
	log.Info("supported", "cert types", Slice2Strings(hi.SignatureSchemes))
	log.Info("supported", "cert curves", Slice2Strings(hi.SupportedCurves))
	log.Info("supported", "symmetric cypher suites", CipherSuites2Strings(hi.CipherSuites))
	log.Info("supported", "ALPN protocols", hi.SupportedProtos)
}

// TransportSummary summarises the connection transport
func (o LogRenderer) TransportSummary(cs *tls.ConnectionState) {
	log := o.log.WithName("Transport")
	log.Info(
		"agreed",
		"sni", cs.ServerName,
		"version", TLSVersionName(cs.Version),
		"alpn", cs.NegotiatedProtocol,
	)
}

// TransportFull prints full details on the connection transport
func (o LogRenderer) TransportFull(cs *tls.ConnectionState) {
	o.TransportSummary(cs)

	log := o.log.WithName("Transport")
	log.Info("agreed", "symmetric cipher suite", cs.CipherSuite)
}

// HeadSummary summarises the application-layer request header
func (o LogRenderer) HeadSummary(proto, method, host, ua string, url *url.URL, respCode int) {
	log := o.log.WithName("HTTP")
	log.Info(
		"request",
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
	log.Info("request", "proto", r.Proto)
	log.Info("request", "method", r.Method)
	// TODO: break this out into path, all query components, all fragment components (like tty HeadFULL)
	log.Info("request", "uri", r.URL.RequestURI())
	log.Info("request", "host", r.Host)
	for k, v := range r.Header {
		log.Info("header", "name", k, "values", v)
	}
	log.Info("response", "status", respCode)
}

// JWTSummary summarises the JWT in the request
func (o LogRenderer) JWTSummary(tokenErr error, start, end *time.Time, ID, subject, issuer string, audience []string) {
	log := o.log.WithName("Auth").WithName("JWT")

	log.Info(
		"claims",
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
		"signature",
		"algo", sigAlgo,
		"hash", hashAlgo,
	)
}

// BodySummary summarises the application-layer request body
func (o LogRenderer) BodySummary(contentType string, contentLength int64, bs []byte) {
	log := o.log.WithName("Body")
	bodyLen := len(bs)
	printLen := min(bodyLen, 72)

	log.Info("Summary",
		"len", contentLength,
		"type", contentType,
		"content", string(bs[0:printLen]),
		"elided", bodyLen-printLen,
	)
}

// BodyFull prints full contents of the application-layer request body
func (o LogRenderer) BodyFull(contentType string, contentLength int64, bs []byte) {
	log := o.log.WithName("Body")
	log.Info("Full",
		"len", contentLength,
		"type", contentType,
		"content", string(bs),
	)
}
