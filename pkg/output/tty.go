package output

/*
the idea is that this can be used from multiple places, even those that aren't an http daemon (expand to CF worker, envoy filter, etc)
this class should
- low-level methods like SetHops(), SetTLSVersion(), SetCertChain() (used behind an interface so can't be fields)
- functions like IngestHTTPRequest should be in CODEC, make them for lambda etc too
- then methods like printTCP, printTLS, printHTTP - caller's main decides order, flow, etc
- think about control flow so it prints as much as it can in the face of any error - panic/recover, with a custom error type we can throw, essentially for exceptional return? What goroutine do http hooks run on?
*/

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mt-inside/go-usvc"
	"github.com/mt-inside/http-log/pkg/build"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/state"
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

func getTimestamp() string {
	return time.Now().Format("15:04:05")
}
func fmtTimestamp(t *time.Time) string {
	return t.Format("15:04:05")
}

// TtyRenderer is an output implementation that pretty-prints to a tty device
type TtyRenderer struct {
	s TtyStyler
}

// NewTtyRenderer returns a new outputter than pretty-prints to a tty device
func NewTtyRenderer(s TtyStyler) TtyRenderer {
	return TtyRenderer{s}
}

func (o TtyRenderer) Version() {
	fmt.Printf(
		"%s %s\n",
		o.s.Info(getTimestamp()),
		o.s.Noun(build.NameAndVersion()),
	)
}

func (o TtyRenderer) ListenInfo(s *state.DaemonData) {
	fmt.Printf(
		"%s Listening on %s %s\n",
		o.s.Info(fmtTimestamp(s.TransportListenTime)),
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
			o.s.ServingCertChain(codec.ChainFromCertificate(s.TlsServingCertPair))
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

// TransportConnection announces the accepted connection
func (o TtyRenderer) TransportConnection(r *state.RequestData) {
	fmt.Printf(
		"%s Connection %d %s %s -> %s\n",
		o.s.Info(fmtTimestamp(r.TransportConnTime)),
		o.s.Bright(r.TransportConnNo),
		o.s.Noun(r.TransportRemoteAddress.Network()),
		o.s.Addr(r.TransportRemoteAddress.String()),
		o.s.Addr(r.TransportLocalAddress.String()),
	)
}

// TLSNegSummary summarises the TLS negotiation
func (o TtyRenderer) TLSNegSummary(d *state.RequestData) {
	// TODO: class indentPrinter, ctor takes a timestamp which is used for indent 0, ?and others?
	fmt.Printf(
		"%s TLS negotiation: ServerName %s\n",
		o.s.Info(fmtTimestamp(d.TlsNegTime)),
		o.s.Addr(d.TlsServerName),
	)
}

// TLSNegFull prints full details on the TLS negotiation
func (o TtyRenderer) TLSNegFull(r *state.RequestData, s *state.DaemonData) {
	o.TLSNegSummary(r)

	if s.TlsServingSelfSign {
		fmt.Printf("\tpresenting serving cert:\n")
		o.s.ServingCertChain(codec.ChainFromCertificate(r.TlsNegServerCert))
	}

	fmt.Printf("\tsupported versions: %s\n", o.s.List(TLSVersions2Strings(r.TlsNegVersions), o.s.NounStyle))
	// Underlying public/private key type and size (eg rsa:2048) is irrelevant I guess cause it's just a bytestream to this thing, which is just verifying the signature on it. But it will later have to be parsed and understood to key-exchange the symmetric key?
	fmt.Printf("\tsupported cert signature types: %s\n", o.s.List(Slice2Strings(r.TlsNegSignatureSchemes), o.s.NounStyle))
	fmt.Printf("\tsupported cert curves: %s\n", o.s.List(Slice2Strings(r.TlsNegCurves), o.s.NounStyle))
	fmt.Printf("\tsupported symmetric cypher suites: %s\n", o.s.List(CipherSuites2Strings(r.TlsNegCipherSuites), o.s.NounStyle))
	fmt.Printf("\tsupported ALPN protos: %s\n", o.s.List(r.TlsNegALPN, o.s.NounStyle))
}

func (o TtyRenderer) tlsAgreedCommon(d *state.RequestData) {
	fmt.Printf("%s %s sni %s | alpn %s\n",
		o.s.Info(fmtTimestamp(d.TlsAgreedTime)),
		o.s.Noun(TLSVersionName(d.TlsAgreedVersion)),
		o.s.Addr(d.TlsServerName),
		o.s.Noun(d.TlsAgreedALPN),
	)
}

// TLSSummary summarises the connection transport
func (o TtyRenderer) TLSAgreedSummary(r *state.RequestData, s *state.DaemonData) {
	o.tlsAgreedCommon(r)

	if len(r.TlsClientCerts) > 0 {
		//TODO: CertSummaryVerified() (pass in ca, verify, just print valid? YesError() on the the end of the line)
		fmt.Printf("\tclient cert %s\n",
			o.s.CertSummary(r.TlsClientCerts[0]),
		)
	}
}

// TLSFull prints full details on the connection transport
func (o TtyRenderer) TLSAgreedFull(r *state.RequestData, s *state.DaemonData) {
	o.tlsAgreedCommon(r)

	fmt.Printf("\tcypher suite %s\n", o.s.Noun(tls.CipherSuiteName(r.TlsAgreedCipherSuite)))

	if len(r.TlsClientCerts) > 0 {
		fmt.Printf("\tclient cert received\n")
		o.s.ClientCertChainVerified(r.TlsClientCerts, s.TlsClientCA)
	}
}

// HeadSummary summarises the application-layer request header
func (o TtyRenderer) HeadSummary(d *state.RequestData) {
	fmt.Printf(
		"%s HTTP/%s vhost %s | %s %s by %s\n",
		o.s.Info(getTimestamp()),
		o.s.Noun(d.HttpProtocolVersion),
		o.s.Addr(d.HttpHost),
		o.s.Verb(d.HttpMethod),
		// url.Host should be empty for a normal request. TODO assert that it is, investigate the types of req we get if someone thinks we're a proxy and print that info
		o.s.PathElements(d.HttpPath, d.HttpQuery, d.HttpFragment),
		o.s.Noun(d.HttpUserAgent),
	)

	if d.AuthJwt != nil {
		fmt.Printf("%s ", o.s.Info(getTimestamp()))
		o.s.JWTSummary(d.AuthJwt)
		fmt.Printf(" [valid? %s]", o.s.YesErrorWarning(d.AuthJwtErr, errors.Is(d.AuthJwtErr, codec.NoValidationKeyError{})))
		fmt.Println()
	}
}

// HeadFull prints full contents of the application-layer request header
func (o TtyRenderer) HeadFull(d *state.RequestData) {
	fmt.Printf(
		"%s HTTP/%s vhost %s | %s %s\n",
		o.s.Info(getTimestamp()),
		o.s.Noun(d.HttpProtocolVersion),
		o.s.Addr(d.HttpHost),
		o.s.Verb(d.HttpMethod),
		o.s.Addr(d.HttpPath),
	)

	if len(d.HttpQuery) > 0 {
		fmt.Println("Query")
		queries, _ := url.ParseQuery(url.QueryEscape(d.HttpQuery))
		//o.b.CheckWarn(err) TODO: we don't have a bios to hand, cause we shouldn't be parsing things this late in the game. Probably means storing duplicate (parsed/unparsed) data in reqData, but that's better than the alternative
		for k, vs := range queries {
			fmt.Printf("\t%s = %v\n", o.s.Addr(k), o.s.Noun(strings.Join(vs, ",")))
		}
	}
	if len(d.HttpFragment) > 0 {
		fmt.Printf("Fragment: %s\n", o.s.Addr(d.HttpFragment))
	}

	fmt.Println("Headers")
	// TODO: make a renderOptinoalArray that does the Info(<none>) if it's empty, and takes a style and prints that for list items (only) using the normal renderColoredList()
	// TODO: Truncate header values (even for Full), have a global --no-truncate option that applies here, to lists, etc (styler should be constructed over it).
	// TODO: truncate to max(72, terminal width)
	for k, vs := range d.HttpHeaders {
		fmt.Printf("\t%s = %v\n", o.s.Addr(k), o.s.Noun(strings.Join(vs, ",")))
	}
	if len(d.HttpHeaders) == 0 {
		fmt.Println(o.s.Info("\t<none>"))
	}

	if d.AuthJwt != nil {
		fmt.Printf("%s ", o.s.Info(getTimestamp()))
		o.s.JWTSummary(d.AuthJwt)
		fmt.Println()

		sigAlgo, hashAlgo := codec.JWTSignatureInfo(d.AuthJwt)
		fmt.Printf("\tSignature %s (hash %s)\n", o.s.Noun(sigAlgo), o.s.Noun(hashAlgo))

		fmt.Println("\tvalid?", o.s.YesErrorWarning(d.AuthJwtErr, errors.Is(d.AuthJwtErr, codec.NoValidationKeyError{})))
	}

	// TODO: print the path the req has come on: x-forwarded-for, via, etc

}

func (o TtyRenderer) bodyCommon(r *state.RequestData, bodyLen int) {
	fmt.Printf(
		"%s HTTP request body: alleged %d bytes of %s, actual length read %d\n",
		o.s.Info(fmtTimestamp(r.HttpBodyTime)),
		o.s.Bright(r.HttpContentLength),
		o.s.Noun(r.HttpContentType),
		o.s.Bright(bodyLen),
	)
}

// BodySummary summarises the application-layer request body
func (o TtyRenderer) BodySummary(r *state.RequestData) {
	bodyLen := len(r.HttpBody)

	o.bodyCommon(r, bodyLen)

	printLen := usvc.MinInt(bodyLen, 72)

	// TODO: ditto hex option in Full, but print array syntax? However many chars would make the rendered array printLen long
	fmt.Printf("%v", string(r.HttpBody[0:printLen])) // assumes utf8
	if bodyLen > printLen {
		fmt.Printf("<%d bytes elided>", bodyLen-printLen)
	}

	if bodyLen > 0 {
		fmt.Println()
	}
}

// BodyFull prints full contents of the application-layer request body
func (o TtyRenderer) BodyFull(r *state.RequestData) {
	bodyLen := len(r.HttpBody)

	o.bodyCommon(r, bodyLen)

	// TODO: option for hex dump (must be a lib for that?). Do automatically when utf8 decode fails
	fmt.Printf("%v", string(r.HttpBody)) // assumes utf8

	if bodyLen > 0 {
		fmt.Println()
	}
}

func (o TtyRenderer) ResponseSummary(r *state.ResponseData) {
	if r.PassthroughURL != nil {
		fmt.Printf(
			"%s Proxy to %s (response is forwarded)\n",
			o.s.Info(fmtTimestamp(&r.ProxyRequestTime)),
			o.s.Noun(r.PassthroughURL.String()),
		)
	}
	fmt.Printf(
		"%s Responding with %s\n",
		o.s.Info(fmtTimestamp(&r.HttpHeaderTime)),
		o.s.Noun(fmt.Sprintf("%d %s", r.HttpStatusCode, http.StatusText(r.HttpStatusCode))),
	)
	// - Don't give any more info about connection to upstream and its response; use print-cert if you wanna do that
}
func (o TtyRenderer) ResponseFull(r *state.ResponseData) {
	if r.PassthroughURL != nil {
		fmt.Printf(
			"%s Proxy to %s (response is forwarded)\n",
			o.s.Info(fmtTimestamp(&r.ProxyRequestTime)),
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
		o.s.Info(fmtTimestamp(&r.HttpHeaderTime)),
		o.s.Noun(fmt.Sprintf("%d %s", r.HttpStatusCode, http.StatusText(r.HttpStatusCode))),
	)
	fmt.Printf(
		"%s HTTP response body: attempting %d bytes of %s, actual length written %d\n",
		o.s.Info(fmtTimestamp(&r.HttpBodyTime)),
		o.s.Bright(r.HttpContentLength),
		o.s.Noun(r.HttpContentType),
		o.s.Bright(r.HttpBodyLen),
	)
	// - Don't give any more info about connection to upstream and its response; use print-cert if you wanna do that
}
