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
	b        output.Bios
	op       output.Renderer
	opOpts   output.RendererOpts
	reqData  *state.RequestData
	respData *state.ResponseData
	srvData  *state.DaemonData
	next     http.Handler
}

func NewLogMiddle(
	b output.Bios,
	op output.Renderer,
	opOpts output.RendererOpts,
	reqData *state.RequestData,
	respData *state.ResponseData,
	srvData *state.DaemonData,
	next http.Handler,
) http.Handler {
	return &LogMiddle{
		b,
		op,
		opOpts,
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

	now := time.Now()
	var err error
	lm.reqData.HttpBody, err = io.ReadAll(r.Body)
	lm.reqData.HttpBodyTime = &now
	lm.b.Unwrap(err) // TODO: shouldn't kill things, should be saved in reqData (NB: req, not resp here) and printed later

	/* Next */

	lm.next.ServeHTTP(w, r)

	/* Request-response is over */

	/* Enrich */

	lm.reqData.HttpHops = parser.Hops(lm.b, lm.reqData, lm.srvData)
	lm.reqData.AuthOIDC, lm.reqData.AuthJwt, lm.reqData.AuthJwtErr = enricher.OIDCInfo(lm.b, lm.reqData)
	if !lm.reqData.AuthOIDC {
		// was no OIDC token, look for "normal" bearer ones
		lm.reqData.AuthJwt, lm.reqData.AuthJwtErr = parser.JWT(lm.b, r, lm.srvData.AuthJwtValidateKey)
	}

	/* Print */

	lm.output()
}

func (lm LogMiddle) output() {

	if lm.opOpts.ConnectionSummary {
		lm.op.TransportSummary(lm.reqData)
	} else if lm.opOpts.ConnectionFull {
		lm.op.TransportFull(lm.reqData)
	}

	if lm.srvData.TlsOn {
		if lm.opOpts.NegotiationFull {
			lm.op.TLSNegFull(lm.reqData, lm.srvData)
		} else if lm.opOpts.NegotiationSummary {
			lm.op.TLSNegSummary(lm.reqData)
		}
		if lm.opOpts.TLSFull {
			lm.op.TLSAgreedFull(lm.reqData, lm.srvData)
		} else if lm.opOpts.TLSSummary {
			// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
			lm.op.TLSAgreedSummary(lm.reqData, lm.srvData)
		}
	}

	if lm.opOpts.HeadFull {
		lm.op.HeadFull(lm.reqData)
	} else if lm.opOpts.HeadSummary {
		// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
		lm.op.HeadSummary(lm.reqData)
	}

	// Print only if the method would traditionally have a body
	if (lm.opOpts.BodyFull || lm.opOpts.BodySummary) && (lm.reqData.HttpMethod == http.MethodPost || lm.reqData.HttpMethod == http.MethodPut || lm.reqData.HttpMethod == http.MethodPatch) {
		if lm.opOpts.BodyFull {
			lm.op.BodyFull(lm.reqData)
		} else if lm.opOpts.BodySummary {
			lm.op.BodySummary(lm.reqData)
		}
	}

	if lm.opOpts.ResponseFull {
		lm.op.ResponseFull(lm.respData)
	} else if lm.opOpts.ResponseSummary {
		lm.op.ResponseSummary(lm.respData)
	}
}
