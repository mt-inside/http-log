package output

import (
	"crypto/tls"
	"net/http"
	"net/url"

	"github.com/go-logr/logr"
)

// Log is an output implementation that logs using zapr
type Log struct{}

// TLSNegFull prints full details on the TLS negotiation
func (o Log) TLSNegFull(log logr.Logger, hi *tls.ClientHelloInfo) {
	log.Info("Transport", "TLS client supported versions", renderTLSVersionNames(hi.SupportedVersions))
	log.Info("Transport", "TLS client supported ALPN protocols", hi.SupportedProtos)
}

// TransportFull prints full details on the connection transport
func (o Log) TransportFull(log logr.Logger, cs *tls.ConnectionState) {
	log.Info("Transport", "SNI", cs.ServerName)
}

// TransportSummary summarises the connection transport
func (o Log) TransportSummary(log logr.Logger, cs *tls.ConnectionState) {
	log.Info("Transport", "SNI", cs.ServerName)
}

// HeadFull prints full contents of the application-layer request header
func (o Log) HeadFull(log logr.Logger, r *http.Request, respCode int) {
	log.Info("Header", "Name", "proto", "Values", r.Proto)
	log.Info("Header", "Name", "method", "Values", r.Method)
	log.Info("Header", "Name", "host", "Values", r.Host)
	log.Info("Header", "Name", "path", "Values", r.RequestURI)
	log.Info("Header", "Name", "response-code", "Value", respCode)
	for k, v := range r.Header {
		log.Info("Header", "Name", k, "Values", v)
	}
}

// HeadSummary summarises the application-layer request header
func (o Log) HeadSummary(log logr.Logger, proto, method, host, ua string, url *url.URL, respCode int) {
	log.Info(
		"Headers summary",
		"proto", proto,
		"method", method,
		"host", host,
		"url", url.String(),
		"user-agent", ua,
		"response-code", respCode,
	)
}

// BodyFull prints full contents of the application-layer request body
func (o Log) BodyFull(log logr.Logger, contentType string, contentLength int64, bs []byte) {
	log.Info("Body",
		"len", contentLength,
		"type", contentType,
		"content", string(bs),
	)
}

// BodySummary summarises the application-layer request body
func (o Log) BodySummary(log logr.Logger, contentType string, contentLength int64, bs []byte) {
	bodyLen := len(bs)
	printLen := min(bodyLen, 72)

	log.Info("Body Summary",
		"len", contentLength,
		"type", contentType,
		"content", string(bs[0:printLen]),
		"elided", bodyLen-printLen,
	)
}
