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
