package output

import (
	"crypto/tls"
	"net/http"
	"net/url"

	"github.com/go-logr/logr"
)

type Log struct{}

func (o Log) TLSNegFull(log logr.Logger, hi *tls.ClientHelloInfo) {
	log.Info("Transport", "TLS client supported versions", renderTlsVersionNames(hi.SupportedVersions))
	log.Info("Transport", "TLS client supported ALPN protocols", hi.SupportedProtos)
}
func (o Log) TransportFull(log logr.Logger, cs *tls.ConnectionState) {
	log.Info("Transport", "SNI", cs.ServerName)
}
func (o Log) TransportSummary(log logr.Logger, cs *tls.ConnectionState) {
	log.Info("Transport", "SNI", cs.ServerName)
}

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

func (o Log) BodyFull(log logr.Logger, contentType string, r *http.Request, bs []byte) {
	log.Info("Body",
		"len", r.ContentLength,
		"type", contentType,
		"content", string(bs),
	)
}
func (o Log) BodySummary(log logr.Logger, contentType string, contentLength int64, method string, bs []byte) {
	bodyLen := len(bs)
	printLen := min(bodyLen, 72)

	log.Info("Body Summary",
		"len", contentLength,
		"type", contentType,
		"content", string(bs[0:printLen]),
		"elided", bodyLen-printLen,
	)
}
