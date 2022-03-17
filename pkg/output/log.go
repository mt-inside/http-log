package output

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-logr/logr"
)

// Log is an output implementation that logs using zapr
type Log struct {
	log logr.Logger
}

// NewLog returns a new outputter than logs using zapr
func NewLog(log logr.Logger) Log {
	return Log{log}
}

// TLSNegSummary summarises the TLS negotiation
func (o Log) TLSNegSummary(hi *tls.ClientHelloInfo) {
	log := o.log.WithName("Transport")
	log.Info("negotiation", "sni", hi.ServerName)
}

// TLSNegFull prints full details on the TLS negotiation
func (o Log) TLSNegFull(hi *tls.ClientHelloInfo) {
	o.TLSNegSummary(hi)

	log := o.log.WithName("Transport")
	log.Info("supported", "versions", renderTLSVersionNames(hi.SupportedVersions))
	// On the use of %v
	// - this Just Works - sees its and array of fmt.Stringers, gets on with it
	// - logr docs strongly imply that .String() will be called on a passed object, but I think that's shallow; does the object in hand implement fmt.Stringer; won't look for an array of fmt.Stringers
	// - logr has a Marshaler interface that you can implement to override printing behaviour, but in Go we can't implement that for []Foo
	// - can't write a generic method that maps Foo -> string cause there's no variance on arrays so can't pass []T as []interface{} (or []Stringer)
	// - TODO KISS: renderFoo() functionS that all take their specfic type and go []Foo -> []string. Can then be used here and passed to renderStyledList() in TTY + print-cert
	log.Info("supported", "cert types", fmt.Sprintf("%v", hi.SignatureSchemes))
	log.Info("supported", "cert curves", fmt.Sprintf("%v", hi.SupportedCurves))
	log.Info("supported", "symmetric cypher suites", renderCipherSuiteNames(hi.CipherSuites))
	log.Info("supported", "ALPN protocols", hi.SupportedProtos)
}

// TransportSummary summarises the connection transport
func (o Log) TransportSummary(cs *tls.ConnectionState) {
	log := o.log.WithName("Transport")
	log.Info(
		"agreed",
		"sni", cs.ServerName,
		"version", tlsVersionName(cs.Version),
		"alpn", cs.NegotiatedProtocol,
	)
}

// TransportFull prints full details on the connection transport
func (o Log) TransportFull(cs *tls.ConnectionState) {
	o.TransportSummary(cs)

	log := o.log.WithName("Transport")
	log.Info("agreed", "symmetric cipher suite", cs.CipherSuite)
}

// HeadSummary summarises the application-layer request header
func (o Log) HeadSummary(proto, method, host, ua string, url *url.URL, respCode int) {
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
func (o Log) HeadFull(r *http.Request, respCode int) {
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

// BodySummary summarises the application-layer request body
func (o Log) BodySummary(contentType string, contentLength int64, bs []byte) {
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
func (o Log) BodyFull(contentType string, contentLength int64, bs []byte) {
	log := o.log.WithName("Body")
	log.Info("Full",
		"len", contentLength,
		"type", contentType,
		"content", string(bs),
	)
}
