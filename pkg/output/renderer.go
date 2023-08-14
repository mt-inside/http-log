package output

import "github.com/mt-inside/http-log/pkg/state"

type RendererOpts struct {
	ConnectionSummary  bool `short:"l" long:"connection" description:"Print summary of connection (eg TCP) information"`
	ConnectionFull     bool `short:"L" long:"connection-full" description:"Print all connection (eg TCP) information"`
	NegotiationSummary bool `short:"n" long:"negotiation" description:"Print transport (eg TLS) setup negotiation summary, notable the SNI ServerName being requested"`
	NegotiationFull    bool `short:"N" long:"negotiation-full" description:"Print transport (eg TLS) setup negotiation values, ie what both sides offer to support"`
	TLSSummary         bool `short:"t" long:"tls" description:"Print important agreed TLS parameters"`
	TLSFull            bool `short:"T" long:"tls-full" description:"Print all agreed TLS parameters"`
	HeadSummary        bool `short:"m" long:"head" description:"Print important HTTP request metadata"`
	HeadFull           bool `short:"M" long:"head-full" description:"Print all HTTP request metadata"`
	BodySummary        bool `short:"b" long:"body" description:"Print truncated HTTP request body"`
	BodyFull           bool `short:"B" long:"body-full" description:"Print full HTTP request body"`
	ResponseSummary    bool `short:"r" long:"response" description:"Print summary of HTTP response"`
	ResponseFull       bool `short:"R" long:"response-full" description:"Print full information about HTTP response"`
}

type Renderer interface {
	Output(srvData *state.DaemonData, reqData *state.RequestData, respData *state.ResponseData)

	ListenInfo(d *state.DaemonData)

	// TODO: then start moving things around, eg Hops with connection, HSTS with TLS (is a print-cert thing but that needs the same treatment)
	TransportSummary(d *state.RequestData)
	TransportFull(d *state.RequestData)
	TLSNegSummary(d *state.RequestData)
	TLSNegFull(r *state.RequestData, s *state.DaemonData)
	TLSAgreedSummary(r *state.RequestData, s *state.DaemonData)
	TLSAgreedFull(r *state.RequestData, s *state.DaemonData)
	HeadSummary(d *state.RequestData)
	HeadFull(d *state.RequestData)
	BodySummary(d *state.RequestData)
	BodyFull(d *state.RequestData)
	ResponseSummary(d *state.ResponseData)
	ResponseFull(d *state.ResponseData)
}
