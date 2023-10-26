package handlers

import (
	"io"
	"net/http"
	"time"

	"github.com/tetratelabs/telemetry"

	"github.com/mt-inside/http-log/internal/ctxt"
	"github.com/mt-inside/http-log/pkg/enricher"
	"github.com/mt-inside/http-log/pkg/extractor"
	"github.com/mt-inside/http-log/pkg/parser"
)

type LogMiddle struct {
	next http.Handler
}

func NewLogMiddle(
	next http.Handler,
) http.Handler {
	return &LogMiddle{
		next,
	}
}

/* This is your main driver func */
func (lm LogMiddle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := log.With(telemetry.KeyValuesFromContext(ctx)...)

	log.Debug("LogMiddle::ServeHTTP()")

	srvData := ctxt.SrvDataFromContext(ctx)
	reqData := ctxt.ReqDataFromContext(ctx)

	/* Record request info */

	extractor.HttpRequest(r, srvData, reqData)

	// TODO: h2c upgraded requests (eg from curl --http2, to us running plaintext without --http-11) stall here. If you ctrl-c curl (ie close the pipe) then we will show the right stuff. So reading the body is blocking after the h2c uprade. Read the h2c docs re closed bodies and what you're meant to do.
	reqData.HttpBody, reqData.HttpBodyErr = io.ReadAll(r.Body)
	reqData.HttpBodyTime = time.Now()

	/* Next - our "action" handler */

	lm.next.ServeHTTP(w, r)

	/* Parse & Enrich */

	reqData.HttpHops = parser.Hops(ctx, reqData, srvData)
	reqData.AuthOIDC, _, reqData.AuthJwt, reqData.AuthJwtErr = enricher.OIDCInfo(ctx, reqData)
	if !reqData.AuthOIDC {
		// was no OIDC token, look for "normal" bearer ones
		reqData.AuthJwt, reqData.AuthJwtErr = parser.JWT(ctx, r, srvData.AuthJwtValidateKey)
	}

	/* Print */

	// Printing is done when ConnState(closed)

	/* Done */

	ctxt.CtxCancelFromContext(ctx)()
}
