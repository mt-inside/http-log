package output

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"

	"github.com/go-logr/logr"
)

/* TODO
* these should be PrintHead[Summary,Body] etc, and should take spelled-out arguments
* codec should contain methods to extract them from http.Request etc
*
* this also needs .PrintCertSummary,Full from daemon / print-cert
 */

func getTimestamp() string {
	return time.Now().Format("15:04:05")
}

type tty struct {
	au aurora.Aurora
}

func NewTty(color bool) tty {
	return tty{aurora.NewAurora(color)}
}

func (o tty) TLSNegFull(log logr.Logger, hi *tls.ClientHelloInfo) {
	fmt.Printf("TLS negotiation\n")
	fmt.Printf("\tsupported versions: %v\n", renderTlsVersionNames(hi.SupportedVersions))
	fmt.Printf("\tsupported cert types: %v\n", hi.SignatureSchemes)
	fmt.Printf("\tsupported cert curves: %v\n", hi.SupportedCurves)
	fmt.Printf("\tsupported ALPN protos: %v\n", hi.SupportedProtos)
}

func (o tty) TransportFull(log logr.Logger, cs *tls.ConnectionState) {
	fmt.Printf("%s %s sni %s alpn %s\n",
		o.au.BrightBlack(getTimestamp()),
		o.au.Blue(tlsVersionName(cs.Version)),
		o.au.Red(cs.ServerName),
		o.au.Green(cs.NegotiatedProtocol),
	)
	fmt.Printf("\tcypher suite %s\n", o.au.Blue(tls.CipherSuiteName(cs.CipherSuite)))

	// TODO add client cert if present, using routines from lb-checker
}

func (o tty) TransportSummary(log logr.Logger, cs *tls.ConnectionState) {
	// TODO use pretty-print from checktls2 in lb-checker
	fmt.Printf("%s %s sni %s apln %s\n",
		o.au.BrightBlack(getTimestamp()),
		o.au.Blue(tlsVersionName(cs.Version)),
		o.au.Red(cs.ServerName),
		o.au.Green(cs.NegotiatedProtocol),
	)
}

func (o tty) HeadFull(log logr.Logger, r *http.Request, respCode int) {
	fmt.Printf(
		"%s %s %s %s %s => %s\n",
		o.au.BrightBlack(getTimestamp()),
		o.au.Blue(r.Proto),
		o.au.Green(r.Method),
		o.au.Red(r.Host),
		o.au.Cyan(r.URL.String()), // unless the request is in the weird proxy form or whatever, this will only contain a path; scheme, host etc will be empty
		o.au.Magenta(fmt.Sprintf("%d %s", respCode, http.StatusText(respCode))),
	)

	fmt.Println("Headers")
	for k, vs := range r.Header {
		fmt.Printf("\t%s = %v\n", k, strings.Join(vs, ","))
	}
	if len(r.Header) == 0 {
		fmt.Println("\t<none>")
	}

	if len(r.URL.Query()) > 0 {
		fmt.Println("Query")
		for k, vs := range r.URL.Query() {
			fmt.Printf("\t%s = %v\n", k, strings.Join(vs, ","))
		}
	}

	if len(r.URL.RawFragment) > 0 {
		fmt.Printf("Fragment: %s\n", r.URL.RawFragment)
	}
}
func (o tty) HeadSummary(log logr.Logger, proto, method, host, ua string, url *url.URL, respCode int) {
	// TODO render # and ? iff there are query and fragment bits
	fmt.Printf(
		"%s %s %s %s %s %s %s by %s => %s\n",
		o.au.BrightBlack(getTimestamp()),
		o.au.Blue(proto),
		o.au.Green(method),
		o.au.Red(host),
		o.au.Cyan(url.Path),
		o.au.Yellow(url.RawQuery),
		o.au.Red(url.RawFragment),
		o.au.Cyan(ua),
		o.au.Magenta(fmt.Sprintf("%d %s", respCode, http.StatusText(respCode))),
	)
}
func (o tty) BodyFull(log logr.Logger, contentType string, contentLength int64, method string, bs []byte) {
	bodyLen := len(bs)

	// Print only if the method would traditionally have a body, or one has been sent
	if !(method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch) && bodyLen == 0 {
		return
	}

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
func (o tty) BodySummary(log logr.Logger, contentType string, contentLength int64, method string, bs []byte) {
	bodyLen := len(bs)
	printLen := min(bodyLen, 72)

	// Print only if the method would traditionally have a body, or one has been sent
	if !(method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch) && bodyLen == 0 {
		return
	}

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
