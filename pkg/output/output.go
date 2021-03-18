package output

import (
	"net/http"

	"github.com/go-logr/logr"
)

type Output interface {
	HeadSummary(log logr.Logger, proto, method, path, ua string)
	HeadFull(log logr.Logger, r *http.Request)
	BodySummary(log logr.Logger, contentType string, contentLength int64, body string)
	BodyFull(log logr.Logger, contentType string, r *http.Request, body string)
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
