package output

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/state"
	"github.com/mt-inside/http-log/pkg/utils"
)

/* TODO
* these should be PrintHead[Summary,Body] etc, and should take spelled-out arguments
* codec should contain methods to extract them from http.Request, lambda etc (see how JWT works)
*
* colors: make a shared module styles
* - use in print-cert
*
* make a styler::UrlPath(*net.URL)
* - use in p-c (it should be parsing its path into a URL (found a method for that? copied the path,query,frag components a la stdlib))
*
* styler::List
*   - unit test this! Check the case where the list is short and we don't truncate, check moving the truncate/item boundaries over each other
*
* X no styler iface
* X BIOS iface (checks, banner)
* - is like commonRenderer - should have evertying that prints. (whole line, multi-line)
*   - only drivers should be calling bios. If func is called by a renderer, it goes on styler
*   - X check: aurora should only be imported by styler
* - Everything that returns a Value is on Styler (no iface case logStyler will return []string)
*   - if it adds color it MUST add a value so that log things don't call them by accident
* - Evertyhing that returns a string is in render_utils (logRenderers/Bios prolly call render_utils direct skipping a stlyer)
*   - Stylers format and add color, intra-line
* X BIOSTty(stlyer)
* X BIOSLog(logr)
* X httpLogRenderer iface
* X httplogRendererTty(stlyer)
* X httoLogRenderrerLog(logr)
* driver - the two mains, call codec, bios, renderer
* p-c tests is basically driver and renderer (cause it only does tty), so give it a stlyer and a bios
* - smell for renderers to get a BIOS cause they shouldn't be dealing with errors
* X renderUtils file: iplist->stringlist etc
* - styler: colorizelist etc
* - maybe a logStyler which can eg have YesNo; timefmt; take a string list, limit len, aggregate or whatever for passing to logr
 */

// TtyRenderer is an output implementation that pretty-prints to a tty device
type TtyRenderer struct {
	s      TtyStyler
	opOpts RendererOpts
}

// NewTtyRenderer returns a new outputter than pretty-prints to a tty device
func NewTtyRenderer(s TtyStyler, opOpts RendererOpts) TtyRenderer {
	return TtyRenderer{s, opOpts}
}

func (o TtyRenderer) Output(srvData *state.DaemonData, reqData *state.RequestData, respData *state.ResponseData) {
	// TODO: like print-cert, we need to get an idea of "how far we got" through these stages, and only print the appropriate ones
	// - eg if something fails we often end up printing lots of ugly <nones>
	// - and sometimes it crashes, eg run -K=ecdsa (self-sign enabled), and hit it with a plaintext request. Something somewhere emits "http: TLS handshake error from 10.244.120.92:48838: tls: first record does not look like a TLS handshake", but then we try to print TLS stuff, and as it happens, blow up on r.TlsNegServerCert being nil

	if o.opOpts.ConnectionSummary {
		o.TransportSummary(reqData)
	} else if o.opOpts.ConnectionFull {
		o.TransportFull(reqData)
	}

	if srvData.TlsOn {
		if o.opOpts.NegotiationFull {
			o.TLSNegFull(reqData, srvData)
		} else if o.opOpts.NegotiationSummary {
			o.TLSNegSummary(reqData)
		}
		if o.opOpts.TLSFull {
			o.TLSAgreedFull(reqData, srvData)
		} else if o.opOpts.TLSSummary {
			// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
			o.TLSAgreedSummary(reqData, srvData)
		}
	}

	if o.opOpts.HeadFull {
		o.HeadFull(reqData)
	} else if o.opOpts.HeadSummary {
		// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
		o.HeadSummary(reqData)
	}

	// Print only if the method would traditionally have a body
	if (o.opOpts.BodyFull || o.opOpts.BodySummary) && (reqData.HttpMethod == http.MethodPost || reqData.HttpMethod == http.MethodPut || reqData.HttpMethod == http.MethodPatch) {
		if o.opOpts.BodyFull {
			o.BodyFull(reqData)
		} else if o.opOpts.BodySummary {
			o.BodySummary(reqData)
		}
	}

	if o.opOpts.ResponseFull {
		o.ResponseFull(respData)
	} else if o.opOpts.ResponseSummary {
		o.ResponseSummary(respData)
	}
}

func (o TtyRenderer) ListenInfo(s *state.DaemonData) {
	fmt.Printf(
		"%s Listening on %s %s\n",
		o.s.Timestamp(s.TransportListenTime, TimestampAbsolute, nil),
		o.s.Noun(s.TransportListenAddress.Network()),
		o.s.Addr(s.TransportListenAddress.String()),
	)

	if s.TlsOn {
		if s.TlsServingSelfSign {
			fmt.Printf(
				"\tTLS serving CA cert: %s\n",
				o.s.CertSummary(codec.HeadFromCertificate(s.TlsServingCertPair)),
			)
		} else {
			fmt.Printf("\tTLS serving cert:\n")
			fmt.Print(o.s.ServingCertChain(codec.ChainFromCertificate(s.TlsServingCertPair)))
		}
		if s.TlsClientCA != nil {
			fmt.Printf(
				"\tTLS client CA cert: %s\n",
				o.s.CertSummary(s.TlsClientCA),
			)
		}
	}
	if s.AuthJwtValidateKey != nil {
		fmt.Printf(
			"\tJWT validation public key: %s\n",
			o.s.PublicKeySummary(s.AuthJwtValidateKey),
		)
	}

	fmt.Println()
}

// TransportSummary summarises the TCP connection details
func (o TtyRenderer) TransportSummary(r *state.RequestData) {
	fmt.Printf(
		"%s Connection %s %s %s -> %s\n",
		o.s.Timestamp(r.TransportConnTime, TimestampAbsolute, nil),
		o.s.Bright(r.TransportConnNo),
		o.s.Noun(r.TransportRemoteAddress.Network()),
		o.s.Addr(r.TransportRemoteAddress.String()),
		o.s.Addr(r.TransportLocalAddress.String()),
	)
}

// TransportFull prints full details on the TCP connection
func (o TtyRenderer) TransportFull(r *state.RequestData) {
	fmt.Printf(
		"%s Connection %s\n",
		o.s.Timestamp(r.TransportConnTime, TimestampAbsolute, nil),
		o.s.Bright(r.TransportConnNo),
	)

	if r.TransportProxyProtocol {
		fmt.Printf("\tConnection used Proxy Protocol v%s\n", o.s.Noun(r.TransportProxyProtocolVersion))
	}

	for i, hop := range r.HttpHops {
		proto := "http"
		if hop.TLS {
			proto = "https"
		}
		if i == 0 {
			fmt.Printf(
				"%s (%s)\n",
				o.s.Addr(net.JoinHostPort(hop.ClientHost, hop.ClientPort)),
				o.s.Noun(hop.ClientAgent),
			)
		}
		fmt.Printf(
			"  --[%s/%s]->\n",
			o.s.Noun(proto),
			o.s.Noun(hop.Version),
		)
		fmt.Printf(
			"%s (%s)\n",
			o.s.Addr(net.JoinHostPort(hop.ServerHost, hop.ServerPort)),
			o.s.Noun(hop.ServerAgent),
		)
	}
}

// TLSNegSummary summarises the TLS negotiation
func (o TtyRenderer) TLSNegSummary(d *state.RequestData) {
	// TODO: class indentPrinter, ctor takes a timestamp which is used for indent 0, ?and others?
	fmt.Printf(
		"%s TLS negotiation: ServerName %s\n",
		o.s.Timestamp(d.TlsNegTime, TimestampAbsolute, nil),
		o.s.Addr(d.TlsServerName),
	)
}

// TLSNegFull prints full details on the TLS negotiation
func (o TtyRenderer) TLSNegFull(r *state.RequestData, s *state.DaemonData) {
	o.TLSNegSummary(r)

	if s.TlsServingSelfSign {
		fmt.Printf("\tpresenting serving cert: %s\n", o.s.ServingCertChain(codec.ChainFromCertificate(r.TlsNegServerCert)))
	}

	fmt.Printf("\tsupported versions: %s\n", o.s.List(utils.Map(r.TlsNegVersions, tls.VersionName), NounStyle))
	// Underlying public/private key type and size (eg rsa:2048) is irrelevant I guess cause it's just a bytestream to this thing, which is just verifying the signature on it. But it will later have to be parsed and understood to key-exchange the symmetric key?
	fmt.Printf("\tsupported cert signature types: %s\n", o.s.List(utils.MapToString(r.TlsNegSignatureSchemes), NounStyle))
	fmt.Printf("\tsupported cert curves: %s\n", o.s.List(utils.MapToString(r.TlsNegCurves), NounStyle))
	fmt.Printf("\tsupported symmetric cypher suites: %s\n", o.s.List(utils.Map(r.TlsNegCipherSuites, tls.CipherSuiteName), NounStyle))
	fmt.Printf("\tsupported ALPN protos: %s\n", o.s.List(r.TlsNegALPN, NounStyle))
}

func (o TtyRenderer) tlsAgreedCommon(d *state.RequestData) {
	fmt.Printf("%s %s sni %s => alpn %s",
		o.s.Timestamp(d.TlsAgreedTime, TimestampAbsolute, nil),
		o.s.Noun(tls.VersionName(d.TlsAgreedVersion)),
		o.s.Addr(d.TlsServerName),
		o.s.Noun(d.TlsAgreedALPN),
	)
}

// TLSSummary summarises the connection transport
func (o TtyRenderer) TLSAgreedSummary(r *state.RequestData, s *state.DaemonData) {
	o.tlsAgreedCommon(r)
	fmt.Println()

	if len(r.TlsClientCerts) > 0 {
		//TODO: CertSummaryVerified() (pass in ca, verify, just print valid? YesError() on the the end of the line)
		fmt.Printf("\tclient cert %s\n",
			o.s.CertSummary(r.TlsClientCerts[0]),
		)
	}
	// TODO: print that we didn't get any client certs (always print), and whether we asked for them or not (print the message as an info or warn)
}

// TLSFull prints full details on the connection transport
func (o TtyRenderer) TLSAgreedFull(r *state.RequestData, s *state.DaemonData) {
	o.tlsAgreedCommon(r)

	fmt.Printf("; cypher suite %s", o.s.Noun(tls.CipherSuiteName(r.TlsAgreedCipherSuite)))
	fmt.Println()

	if len(r.TlsClientCerts) > 0 {
		fmt.Printf("\tclient cert received\n")
		fmt.Print(o.s.VerifiedClientCertChain(r.TlsClientCerts, s.TlsClientCA, true))
	}
}

// HeadSummary summarises the application-layer request header
func (o TtyRenderer) HeadSummary(d *state.RequestData) {
	fmt.Printf(
		"%s HTTP/%s %s %s %s by %s (%s headers, %s cookie values)\n",
		o.s.Timestamp(d.HttpRequestTime, TimestampAbsolute, nil),
		o.s.Noun(d.HttpProtocolVersion),
		o.s.Verb(d.HttpMethod),
		o.s.Addr(d.HttpHost),
		// url.Host should be empty for a normal request. TODO assert that it is, investigate the types of req we get if someone thinks we're a proxy and print that info
		o.s.PathElements(d.HttpPath, d.HttpQuery, d.HttpFragment),
		o.s.Noun(d.HttpUserAgent),
		o.s.Noun(len(d.HttpHeaders)),
		o.s.Noun(len(d.HttpCookies)),
	)

	if d.AuthJwt != nil {
		fmt.Printf("%s %s [valid? %s]\n",
			o.s.Timestamp(d.HttpRequestTime, TimestampAbsolute, nil),
			o.s.JWTSummary(d.AuthJwt),
			o.s.YesError(d.AuthJwtErr),
		)
	}
}

// HeadFull prints full contents of the application-layer request header
func (o TtyRenderer) HeadFull(d *state.RequestData) {
	// TODO: share this fn with header printing in print-cert::responseData.Print

	fmt.Printf(
		"%s HTTP/%s %s %s %s\n",
		o.s.Timestamp(d.HttpRequestTime, TimestampAbsolute, nil),
		o.s.Noun(d.HttpProtocolVersion),
		o.s.Verb(d.HttpMethod),
		o.s.Addr(d.HttpHost),
		o.s.Addr(d.HttpPath),
	)

	if len(d.HttpQuery) > 0 {
		fmt.Println("Query")
		queries, _ := url.ParseQuery(url.QueryEscape(d.HttpQuery))
		//o.b.CheckWarn(err) TODO: this should be in the same place as extractOIDC etc, currently logmiddle
		for k, vs := range queries {
			fmt.Printf("\t%s = %v\n", o.s.Addr(k), o.s.Noun(strings.Join(vs, ",")))
		}
	}
	if len(d.HttpFragment) > 0 {
		fmt.Printf("Fragment: %s\n", o.s.Addr(d.HttpFragment))
	}

	if len(d.HttpHeaders) > 0 {
		fmt.Println("Headers")
	} else {
		fmt.Println("No Headers")
	}
	// TODO: make a renderOptinoalArray that does the Info(<none>) if it's empty, and takes a style and prints that for list items (only) using the normal renderColoredList()
	for k, vs := range d.HttpHeaders {
		for _, v := range vs {
			// We deliberately "unfold" headers with multiple values, however they're sent on the wire (which the library doesn't let us see), as it's easier to read.
			// TODO: truncate values, as they can be long (esp Cookie)
			fmt.Printf("\t%s = %v\n", o.s.Addr(k), o.s.Noun(o.s.Truncate(v)))
		}
	}
	if len(d.HttpHeaders) == 0 {
		fmt.Println(o.s.Info("\t<none>"))
	}

	if len(d.HttpCookies) > 0 {
		fmt.Println("Cookies")
	}
	for n, c := range d.HttpCookies {
		val := c.Value
		decoded := ""
		// Don't actually print the decoded base64, cause it's likely to contain non-printing chars
		if _, err := base64.StdEncoding.DecodeString(val); err == nil {
			decoded = " (valid base64)"
		}
		fmt.Printf("\t%s%s = %s\n", o.s.Addr(n), decoded, o.s.Noun(o.s.Truncate(val)))
	}

	if d.AuthJwt != nil {
		fmt.Printf("%s %s\n", o.s.Timestamp(d.HttpRequestTime, TimestampAbsolute, nil), o.s.JWTSummary(d.AuthJwt))

		// TODO: move these bits into an styler::JWTFull (which calls JWTSummary).
		// - here, and the above JWTSummary call site should call JWTFull
		// - leave JTWSummary public, cause print-cert uses it
		// - print-cert should call JWTFull iff it's in head-full mode
		sigAlgo, hashAlgo := codec.JWTSignatureInfo(d.AuthJwt)
		fmt.Printf("\tSignature %s (hash %s)\n", o.s.Noun(sigAlgo), o.s.Noun(hashAlgo))

		fmt.Printf("\tvalid? %s\n", o.s.YesError(d.AuthJwtErr))
	}

	if d.AuthOIDC {
		fmt.Printf("%s OIDC\n", o.s.Timestamp(d.HttpRequestTime, TimestampAbsolute, nil))
		fmt.Printf("\tDiscovery: IdToken sig algos %s; Supported claims %s\n", o.s.List(d.AuthOIDCDiscoSupportedSigs, NounStyle), o.s.Number(len(d.AuthOIDCDiscoSupportedClaims)))
		fmt.Printf("\tExtra Userinfo (%s/%s): %s\n", o.s.Number(len(d.AuthOIDCUserinfo)), o.s.Number(len(d.AuthOIDCDiscoSupportedClaims)), o.s.Map(d.AuthOIDCUserinfo, NounStyle))
	}

	// TODO: print the path the req has come on: x-forwarded-for, via, etc

}

func (o TtyRenderer) bodyCommon(r *state.RequestData) bool {
	fmt.Printf("Body read ok: %s\n", o.s.YesError(r.HttpBodyErr))

	fmt.Printf(
		"%s HTTP request body: alleged %s bytes of %s, actual length read %s\n",
		o.s.Timestamp(r.HttpBodyTime, TimestampAbsolute, nil),
		o.s.Bright(r.HttpContentLength),
		o.s.Noun(r.HttpContentType),
		o.s.Bright(r.HttpBodyLen),
	)

	return r.HttpBodyErr == nil
}

// BodySummary summarises the application-layer request body
func (o TtyRenderer) BodySummary(r *state.RequestData) {
	if o.bodyCommon(r) {
		printLen := min(r.HttpBodyLen, 72)

		// TODO: ditto hex option in Full, but print array syntax? However many chars would make the rendered array printLen long
		fmt.Printf("%v", string(r.HttpBody[0:printLen])) // assumes utf8
		if r.HttpBodyLen > printLen {
			fmt.Printf("<%d bytes elided>", r.HttpBodyLen-printLen)
		}

		if r.HttpBodyLen > 0 {
			fmt.Println()
		}
	}
}

// BodyFull prints full contents of the application-layer request body
func (o TtyRenderer) BodyFull(r *state.RequestData) {
	if o.bodyCommon(r) {

		// TODO: option for hex dump (must be a lib for that?). Do automatically when utf8 decode fails
		fmt.Printf("%v", string(r.HttpBody)) // assumes utf8

		if r.HttpBodyLen > 0 {
			fmt.Println()
		}
	}
}

func (o TtyRenderer) ResponseSummary(r *state.ResponseData) {
	if r.PassthroughURL != nil {
		fmt.Printf(
			"%s Proxy to %s (response is forwarded)\n",
			o.s.Timestamp(r.ProxyRequestTime, TimestampAbsolute, nil),
			o.s.Noun(r.PassthroughURL.String()),
		)
	}
	fmt.Printf(
		"%s Responding with %s\n",
		o.s.Timestamp(r.HttpHeaderTime, TimestampAbsolute, nil),
		o.s.Noun(fmt.Sprintf("%d %s", r.HttpStatusCode, http.StatusText(r.HttpStatusCode))),
	)
	// - Don't give any more info about connection to upstream and its response; use print-cert if you wanna do that
}
func (o TtyRenderer) ResponseFull(r *state.ResponseData) {
	if r.PassthroughURL != nil {
		fmt.Printf(
			"%s Proxy to %s (response is forwarded)\n",
			o.s.Timestamp(r.ProxyRequestTime, TimestampAbsolute, nil),
			o.s.Noun(r.PassthroughURL.String()),
		)
		fmt.Printf(
			"\t connection %s -> %s\n",
			o.s.Addr(r.PassthroughLocalAddress.String()),
			o.s.Addr(r.PassthroughRemoteAddress.String()),
		)
	}
	fmt.Printf(
		"%s Responding with %s\n",
		o.s.Timestamp(r.HttpHeaderTime, TimestampAbsolute, nil),
		o.s.Noun(fmt.Sprintf("%d %s", r.HttpStatusCode, http.StatusText(r.HttpStatusCode))),
	)
	fmt.Printf(
		"%s HTTP response body: attempting %s bytes of %s, actual length written %s\n",
		o.s.Timestamp(r.HttpBodyTime, TimestampAbsolute, nil),
		o.s.Bright(r.HttpContentLength),
		o.s.Noun(r.HttpContentType),
		o.s.Bright(r.HttpBodyLen),
	)
	// - Don't give any more info about connection to upstream and its response; use print-cert if you wanna do that
}
