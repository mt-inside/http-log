package output

import (
	"net/http"

	"github.com/go-logr/logr"
)

type Log struct{}

func (o Log) HeadFull(log logr.Logger, r *http.Request) {
	log.Info("Header", "Name", "proto", "Values", r.Proto)
	log.Info("Header", "Name", "method", "Values", r.Method)
	log.Info("Header", "Name", "host", "Values", r.Host)
	log.Info("Header", "Name", "path", "Values", r.RequestURI)
	for k, v := range r.Header {
		log.Info("Header", "Name", k, "Values", v)
	}
}
func (o Log) HeadSummary(log logr.Logger, proto, method, path, ua string) {
	log.Info(
		"Headers summary",
		"proto", proto,
		"method", method,
		"path", path,
		"user-agent", ua,
	)
}
func (o Log) BodyFull(log logr.Logger, contentType string, r *http.Request, bs string) {
	log.Info("Body",
		"len", r.ContentLength,
		"type", contentType,
		"content", bs,
	)
}
func (o Log) BodySummary(log logr.Logger, contentType string, contentLength int64, bs string) {
	bodyLen := len(bs)
	printLen := min(bodyLen, 72)

	log.Info("Body Summary",
		"len", contentLength,
		"type", contentType,
		"content", string(bs[0:printLen]),
		"elided", bodyLen-printLen,
	)
}
