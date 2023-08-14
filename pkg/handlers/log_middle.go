package handlers

import (
	"io"
	"net/http"
	"time"

	"github.com/mt-inside/http-log/pkg/enricher"
	"github.com/mt-inside/http-log/pkg/extractor"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/parser"
	"github.com/mt-inside/http-log/pkg/state"
)

type LogMiddle struct {
	op       output.Renderer
	reqData  *state.RequestData
	respData *state.ResponseData
	srvData  *state.DaemonData
	next     http.Handler
}

func NewLogMiddle(
	op output.Renderer,
	reqData *state.RequestData,
	respData *state.ResponseData,
	srvData *state.DaemonData,
	next http.Handler,
) http.Handler {
	return &LogMiddle{
		op,
		reqData,
		respData,
		srvData,
		next,
	}
}

/* This is your main driver func */
func (lm LogMiddle) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	/* Record request info */

	extractor.HttpRequest(r, lm.srvData, lm.reqData)

	lm.reqData.HttpBody, lm.reqData.HttpBodyErr = io.ReadAll(r.Body)
	lm.reqData.HttpBodyTime = time.Now()

	/* Next */

	lm.next.ServeHTTP(w, r)

	/* Parse & Enrich */

	lm.reqData.HttpHops = parser.Hops(lm.reqData, lm.srvData)
	lm.reqData.AuthOIDC, _, lm.reqData.AuthJwt, lm.reqData.AuthJwtErr = enricher.OIDCInfo(lm.reqData)
	if !lm.reqData.AuthOIDC {
		// was no OIDC token, look for "normal" bearer ones
		lm.reqData.AuthJwt, lm.reqData.AuthJwtErr = parser.JWT(r, lm.srvData.AuthJwtValidateKey)
	}

	/* Print */

	lm.op.Output(lm.srvData, lm.reqData, lm.respData)
}
