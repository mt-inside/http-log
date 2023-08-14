package handlers

import (
	"io"
	"net/http"
	"time"

	"github.com/tetratelabs/telemetry"

	"github.com/mt-inside/http-log/internal/ctxt"
	"github.com/mt-inside/http-log/pkg/enricher"
	"github.com/mt-inside/http-log/pkg/extractor"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/parser"
	"github.com/mt-inside/http-log/pkg/state"
)

type LogMiddle struct {
	op      output.Renderer
	srvData *state.DaemonData
	next    http.Handler
}

func NewLogMiddle(
	op output.Renderer,
	srvData *state.DaemonData,
	next http.Handler,
) http.Handler {
	return &LogMiddle{
		op,
		srvData,
		next,
	}
}

/* This is your main driver func */
func (lm LogMiddle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := log.With(telemetry.KeyValuesFromContext(ctx)...)

	log.Debug("LogMiddle::ServeHTTP()")

	reqData := ctxt.ReqDataFromContext(ctx)
	respData := ctxt.RespDataFromContext(ctx)

	/* Record request info */

	extractor.HttpRequest(r, lm.srvData, reqData)

	reqData.HttpBody, reqData.HttpBodyErr = io.ReadAll(r.Body)
	reqData.HttpBodyTime = time.Now()

	/* Next - our "action" handler */

	lm.next.ServeHTTP(w, r)

	/* Parse & Enrich */

	reqData.HttpHops = parser.Hops(ctx, reqData, lm.srvData)
	reqData.AuthOIDC, _, reqData.AuthJwt, reqData.AuthJwtErr = enricher.OIDCInfo(ctx, reqData)
	if !reqData.AuthOIDC {
		// was no OIDC token, look for "normal" bearer ones
		reqData.AuthJwt, reqData.AuthJwtErr = parser.JWT(ctx, r, lm.srvData.AuthJwtValidateKey)
	}

	/* Print */

	lm.op.Output(lm.srvData, reqData, respData)

	/* Done */

	ctxt.CtxCancelFromContext(ctx)()
}
