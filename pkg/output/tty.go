package output

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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

// TtyRenderer is an output implementation that pretty-prints to a tty device
type TtyRenderer struct {
	s TtyStyler
}

// NewTtyRenderer returns a new outputter than pretty-prints to a tty device
func NewTtyRenderer(s TtyStyler) TtyRenderer {
	return TtyRenderer{s}
}

// Connection announces the accepted connection
func (o TtyRenderer) Connection(requestNo uint, c net.Conn) {
	fmt.Printf(
		"%s TCP connection %d from %s\n",
		o.s.Info(getTimestamp()),
		o.s.Bright(requestNo),
		o.s.Addr(c.RemoteAddr().String()),
	)
}

// TLSNegSummary summarises the TLS negotiation
func (o TtyRenderer) TLSNegSummary(hi *tls.ClientHelloInfo) {
	fmt.Printf(
		"%s TLS negotiation: ServerName %s\n",
		o.s.Info(getTimestamp()),
		o.s.Addr(hi.ServerName),
	)
}

// TLSNegFull prints full details on the TLS negotiation
func (o TtyRenderer) TLSNegFull(hi *tls.ClientHelloInfo) {
	o.TLSNegSummary(hi)

	fmt.Printf("\tsupported versions: %s\n", o.s.List(TLSVersions2Strings(hi.SupportedVersions), o.s.NounStyle))
	// Underlying public/private key type and size (eg rsa:2048) is irrelevant I guess cause it's just a bytestream to this thing, which is just verifying the signature on it. But it will later have to be parsed and understood to key-exchange the symmetric key?
	fmt.Printf("\tsupported cert signature types: %s\n", o.s.List(Slice2Strings(hi.SignatureSchemes), o.s.NounStyle))
	fmt.Printf("\tsupported cert curves: %s\n", o.s.List(Slice2Strings(hi.SupportedCurves), o.s.NounStyle))
	fmt.Printf("\tsupported symmetric cypher suites: %s\n", o.s.List(CipherSuites2Strings(hi.CipherSuites), o.s.NounStyle))
	fmt.Printf("\tsupported ALPN protos: %s\n", o.s.List(hi.SupportedProtos, o.s.NounStyle))
}

func (o TtyRenderer) transportCommon(cs *tls.ConnectionState) {
	fmt.Printf("%s sni %s agreed: %s alpn %s\n",
		o.s.Info(getTimestamp()),
		o.s.Addr(cs.ServerName),
		o.s.Noun(TLSVersionName(cs.Version)),
		o.s.Noun(cs.NegotiatedProtocol),
	)
}

// TransportSummary summarises the connection transport
func (o TtyRenderer) TransportSummary(cs *tls.ConnectionState) {
	o.transportCommon(cs)

	if len(cs.PeerCertificates) > 0 {
		fmt.Printf("%s x509 %s\n", o.s.Info(getTimestamp()), o.s.CertSummary(cs.PeerCertificates[0]))
	}
}

// TransportFull prints full details on the connection transport
func (o TtyRenderer) TransportFull(cs *tls.ConnectionState) {
	o.transportCommon(cs)

	fmt.Printf("\tcypher suite %s\n", o.s.Noun(tls.CipherSuiteName(cs.CipherSuite)))

	if len(cs.PeerCertificates) > 0 {
		fmt.Printf("%s x509\n", o.s.Info(getTimestamp()))
		// TODO print cert chain using lb-checker routine - factor that out to ValidateAndPrint(presentedChain, userGivenRoot/nil)
		o.s.ClientCertChain(cs.PeerCertificates)
	}
}

// HeadSummary summarises the application-layer request header
func (o TtyRenderer) HeadSummary(proto, method, vhost, ua string, url *url.URL, respCode int) {
	// TODO render # and ? iff there are query and fragment bits
	fmt.Printf(
		"%s vhost %s: %s %s %s by %s => %s\n",
		o.s.Info(getTimestamp()),
		o.s.Addr(vhost),
		o.s.Noun(proto),
		o.s.Verb(method),
		// url.Host should be empty for a normal request. TODO assert that it is, investigate the types of req we get if someone thinks we're a proxy and print that info
		o.s.UrlPath(url),
		o.s.Noun(ua),
		o.s.Bright(fmt.Sprintf("%d %s", respCode, http.StatusText(respCode))),
	)
}

// HeadFull prints full contents of the application-layer request header
func (o TtyRenderer) HeadFull(r *http.Request, respCode int) {
	fmt.Printf(
		"%s vhost %s: %s %s %s\n",
		o.s.Info(getTimestamp()),
		o.s.Addr(r.Host),
		o.s.Noun(r.Proto),
		o.s.Verb(r.Method),
		o.s.Addr(r.URL.EscapedPath()),
	)

	if len(r.URL.Query()) > 0 {
		fmt.Println("Query")
		for k, vs := range r.URL.Query() {
			fmt.Printf("\t%s = %v\n", o.s.Addr(k), o.s.Noun(strings.Join(vs, ",")))
		}
	}
	if len(r.URL.RawFragment) > 0 {
		fmt.Printf("Fragment: %s\n", o.s.Addr(r.URL.RawFragment))
	}

	fmt.Println("Headers")
	// TODO: make a renderOptinoalArray that does the Info(<none>) if it's empty, and takes a style and prints that for list items (only) using the normal renderColoredList()
	for k, vs := range r.Header {
		fmt.Printf("\t%s = %v\n", o.s.Addr(k), o.s.Noun(strings.Join(vs, ",")))
	}
	if len(r.Header) == 0 {
		fmt.Println(o.s.Info("\t<none>"))
	}

	// TODO: print the path the req has come on: x-forwarded-for, via, etc

	fmt.Printf("=> %s\n", o.s.Noun(fmt.Sprintf("%d %s", respCode, http.StatusText(respCode))))
}

func (o TtyRenderer) jwtCommon(start, end *time.Time, ID, subject, issuer string, audience []string) {

	fmt.Printf("%s JWT [", o.s.Info(getTimestamp()))
	if start != nil {
		fmt.Print(o.s.Time(*start, true))
	} else {
		fmt.Print(o.s.Fail("?").String())
	}
	fmt.Print(" -> ")
	if end != nil {
		fmt.Print(o.s.Time(*end, false))
	} else {
		fmt.Print(o.s.Fail("?").String())
	}
	fmt.Print("]")

	if ID != "" {
		fmt.Printf(" id %s", o.s.Bright(ID))
	}

	if subject != "" {
		fmt.Printf(" subj %s", o.s.Addr(subject))
	}

	if issuer != "" {
		fmt.Printf(" iss %s", o.s.Addr(issuer))
	}

	if len(audience) != 0 {
		fmt.Printf(" aud %s", o.s.List(audience, o.s.AddrStyle))
	}
}

// JWTSummary summarises the JWT in the request
func (o TtyRenderer) JWTSummary(tokenErr error, start, end *time.Time, ID, subject, issuer string, audience []string) {
	o.jwtCommon(start, end, ID, subject, issuer, audience)
	fmt.Printf(" [valid? %s]", o.s.YesError(tokenErr))
	fmt.Println()
}

// JWTFull prints detailed information about the JWT in the request
func (o TtyRenderer) JWTFull(tokenErr error, start, end *time.Time, ID, subject, issuer string, audience []string, sigAlgo, hashAlgo string) {
	o.jwtCommon(start, end, ID, subject, issuer, audience)
	fmt.Println()

	fmt.Printf("\tSignature %s (hash %s)\n", o.s.Noun(sigAlgo), o.s.Noun(hashAlgo))

	fmt.Println("\tvalid?", o.s.YesError(tokenErr))
}

func (o TtyRenderer) bodyCommon(contentType string, contentLength int64, bodyLen int) {
	fmt.Printf(
		"%s Body: alleged %d bytes of %s, actual length read %d\n",
		o.s.Info(getTimestamp()),
		o.s.Bright(contentLength),
		o.s.Noun(contentType),
		o.s.Bright(bodyLen),
	)
}

// BodySummary summarises the application-layer request body
func (o TtyRenderer) BodySummary(contentType string, contentLength int64, bs []byte) {
	bodyLen := len(bs)

	o.bodyCommon(contentType, contentLength, bodyLen)

	printLen := min(bodyLen, 72)

	// TODO: ditto hex option in Full, but print array syntax? However many chars would make the rendered array printLen long
	fmt.Printf("%v", string(bs[0:printLen])) // assumes utf8
	if bodyLen > printLen {
		fmt.Printf("<%d bytes elided>", bodyLen-printLen)
	}

	if bodyLen > 0 {
		fmt.Println()
	}
}

// BodyFull prints full contents of the application-layer request body
func (o TtyRenderer) BodyFull(contentType string, contentLength int64, bs []byte) {
	bodyLen := len(bs)

	o.bodyCommon(contentType, contentLength, bodyLen)

	// TODO: option for hex dump (must be a lib for that?). Do automatically when utf8 decode fails
	fmt.Printf("%v", string(bs)) // assumes utf8

	if bodyLen > 0 {
		fmt.Println()
	}
}
