package handlers

import (
	"net/http"
	"time"

	"github.com/mt-inside/http-log/pkg/build"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/state"
)

type responseHandler struct {
	status         int    // TODO: is a type alias for this?
	responseFormat string // TODO: should be handled internally as an enum
	respData       *state.ResponseData
}

func NewResponseHandler(status int, responseFormat string, respData *state.ResponseData) http.Handler {
	return &responseHandler{status, responseFormat, respData}
}

func (rh responseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	/* Header */

	w.Header().Set("server", build.NameAndVersion())
	bytes, mime := codec.BytesAndMime(rh.status, codec.GetBody(), rh.responseFormat)
	w.Header().Set("Content-Type", mime)
	if rh.status >= 300 && rh.status < 400 {
		// For redirects, Location is basically (actually?) required. Send them to httpbin's redirect path, cause if we send them back to ourself it'll be a loop
		w.Header().Set("location", "https://httpbin.org/status/302")
	}
	w.WriteHeader(rh.status)
	rh.respData.HttpHeaderTime = time.Now()
	rh.respData.HttpStatusCode = rh.status

	/* Body */

	n, _ := w.Write(bytes)
	rh.respData.HttpBodyTime = time.Now()
	rh.respData.HttpContentLength = int64(len(bytes))
	rh.respData.HttpContentType = mime
	rh.respData.HttpBody = bytes
	rh.respData.HttpBodyLen = int64(n)
	// TODO: do an op if n != content-length header. Don't bail out though - best effort is what we want for this
}
