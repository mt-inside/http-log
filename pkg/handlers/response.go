package handlers

import (
	"net/http"
	"time"

	"github.com/tetratelabs/telemetry"

	"github.com/mt-inside/http-log/internal/build"
	"github.com/mt-inside/http-log/internal/ctxt"
	"github.com/mt-inside/http-log/pkg/codec"
)

type responseHandler struct {
	status         int    // stdlib has no special type for this
	responseFormat string // TODO: should be handled internally as an enum
}

func NewResponseHandler(status int, responseFormat string) http.Handler {
	return &responseHandler{status, responseFormat}
}

func (rh responseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := log.With(telemetry.KeyValuesFromContext(ctx)...)

	log.Debug("ResponseHandler::ServeHTTP()")

	respData := ctxt.RespDataFromContext(r.Context())

	/* Header */

	w.Header().Set("server", build.NameAndVersion())
	bytes, mime := codec.BytesAndMime(rh.status, codec.GetBody(), rh.responseFormat)
	w.Header().Set("Content-Type", mime)
	if rh.status >= 300 && rh.status < 400 {
		// For redirects, Location is basically (actually?) required. Send them to httpbin's redirect path, cause if we send them back to ourself it'll be a loop
		w.Header().Set("location", "https://httpbin.org/status/302")
	}
	w.WriteHeader(rh.status)
	respData.HttpHeaderTime = time.Now()
	respData.HttpStatusCode = rh.status

	/* Body */

	n, _ := w.Write(bytes)
	respData.HttpBodyTime = time.Now()
	respData.HttpContentLength = int64(len(bytes))
	respData.HttpContentType = mime
	respData.HttpBody = bytes
	respData.HttpBodyLen = int64(n)
	// TODO: do an op if n != content-length header. Don't bail out though - best effort is what we want for this
}
