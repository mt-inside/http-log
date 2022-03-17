package output

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/logrusorgru/aurora"
)

/* TODO
* these should be PrintHead[Summary,Body] etc, and should take spelled-out arguments
* codec should contain methods to extract them from http.Request, lambda etc
*
* colors: make a shared module styles
* - apply everywhere here
* - use in print-cert
*
* make a styler::UrlPath(*net.URL)
* - use in here, and in p-c (it should be parsing its path into a URL (found a method for that? copied the path,query,frag components a la stdlib))
*
* make the RenderLists more generic
* - renderStyledList(list, o.s.NounStyle / o.s.AddrStyle / etc)
* - renderStyledListTruncate(list, o.s.FooStyle)
*   - roll through the list, rendering, tracking acc + len(item) + len(', ')
*   - when you get to the one you'll be truncating, render item[:trunc-3] in color then non-color ...
*   - if trunc-3 < 0 just print ', ...'
*   - unit test this! Check the case where the list is short and we don't truncate, check moving the truncate/item boundaries over each other
* - renderAddrList() just does the net.Ip -> String map, ditto RenderTLSVersions() etc.
*   - they just return []string cause you might wanna pass that to renderStyledList or you might want it plaintext to log
 */

func getTimestamp() string {
	return time.Now().Format("15:04:05")
}

// Tty is an output implementation that pretty-prints to a tty device
type Tty struct {
	log logr.Logger
	s   Styler
	au  aurora.Aurora // FIXME temp
}

// NewTty returns a new outputter than pretty-prints to a tty device
func NewTty(log logr.Logger, color bool) Tty {
	return Tty{log, NewStyler(aurora.NewAurora(color)), aurora.NewAurora(false)}
}

// TLSNegSummary summarises the TLS negotiation
func (o Tty) TLSNegSummary(hi *tls.ClientHelloInfo) {
	fmt.Printf(
		"%s TLS negotiation: ServerName %s\n",
		o.s.Info(getTimestamp()),
		o.s.Addr(hi.ServerName),
	)
}

// TLSNegFull prints full details on the TLS negotiation
func (o Tty) TLSNegFull(hi *tls.ClientHelloInfo) {
	o.TLSNegSummary(hi)

	fmt.Printf("\tsupported versions: %v\n", renderTLSVersionNames(hi.SupportedVersions))
	// Underlying public/private key type and size (eg rsa:2048) is irrelevant I guess cause it's just a bytestream to this thing, which is just verifying the signature on it. But it will later have to be parsed and understood to key-exchange the symmetric key?
	fmt.Printf("\tsupported cert signature types: %v\n", hi.SignatureSchemes)
	fmt.Printf("\tsupported cert curves: %v\n", hi.SupportedCurves)
	fmt.Printf("\tsupported symmetric cypher suites: %v\n", renderCipherSuiteNames(hi.CipherSuites))
	fmt.Printf("\tsupported ALPN protos: %v\n", hi.SupportedProtos)
}

// TransportSummary summarises the connection transport
func (o Tty) TransportSummary(cs *tls.ConnectionState) {
	fmt.Printf("%s sni %s agreed: %s alpn %s\n",
		o.au.BrightBlack(getTimestamp()),
		o.au.Red(cs.ServerName),
		o.au.Blue(tlsVersionName(cs.Version)),
		o.au.Green(cs.NegotiatedProtocol),
	)

	//TODO: printbasiccertinfo(peercers[0])
}

// TransportFull prints full details on the connection transport
func (o Tty) TransportFull(cs *tls.ConnectionState) {
	o.TransportSummary(cs)
	fmt.Printf("\tcypher suite %s\n", o.au.Blue(tls.CipherSuiteName(cs.CipherSuite)))

	// TODO print cert chain using lb-checker routine - factor that out to ValidateAndPrint(presentedChain, userGivenRoot/nil)
}

// HeadSummary summarises the application-layer request header
func (o Tty) HeadSummary(proto, method, vhost, ua string, url *url.URL, respCode int) {
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
func (o Tty) HeadFull(r *http.Request, respCode int) {
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

	fmt.Printf("=> %s\n", o.au.Magenta(fmt.Sprintf("%d %s", respCode, http.StatusText(respCode))))
}

// func (o Tty) AuthSummary(r *http.Request) {
// 	token, err := request.ParseFromRequest(
// 		r,
// 		request.OAuth2Extractor, // Looks for `Authorization: Bearer foo` or body field `access_token`
// 		func(token *jwt.Token) (interface{}, error) { panic(errors.New("don't call me")) },
// 		request.WithClaims(&jwt.RegisteredClaims{}),
// 		request.WithParser(jwt.NewParser(jwt.WithoutClaimsValidation())),
// 	)

// 	fmt.Println("Token valid?", RenderYesError(err))

// 	spew.Dump(token.Claims)
// 	claims := token.Claims.(*jwt.RegisteredClaims)
// 	fmt.Printf(
// 		"JWT subj %s iss %s [%s -> %s]\n",
// 		o.s.Bright(claims.Subject),
// 		o.s.Bright(claims.Issuer),
// 		RenderTime(claims.NotBefore, true),
// 		RenderTime(claims.ExpiresAt, false),
// 	)
// }

// BodySummary summarises the application-layer request body
func (o Tty) BodySummary(contentType string, contentLength int64, bs []byte) {
	bodyLen := len(bs)
	printLen := min(bodyLen, 72)

	fmt.Printf(
		"%s Body: alleged %d bytes of %s, actual length read %d\n",
		o.au.BrightBlack(getTimestamp()),
		o.au.Cyan(contentLength),
		o.au.Green(contentType),
		o.au.Cyan(bodyLen),
	)

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
func (o Tty) BodyFull(contentType string, contentLength int64, bs []byte) {
	bodyLen := len(bs)

	fmt.Printf(
		"%s Body: alleged %d bytes of %s, actual length read %d\n",
		o.au.BrightBlack(getTimestamp()),
		o.au.Cyan(contentLength),
		o.au.Green(contentType),
		o.au.Cyan(bodyLen),
	)

	// TODO: option for hex dump (must be a lib for that?). Do automatically when utf8 decode fails
	fmt.Printf("%v", string(bs)) // assumes utf8

	if bodyLen > 0 {
		fmt.Println()
	}
}
