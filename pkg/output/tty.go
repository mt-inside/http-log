package output

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/go-logr/logr"
)

type tty struct {
	au aurora.Aurora
}

func NewTty(color bool) tty {
	return tty{aurora.NewAurora(color)}
}

func (o tty) HeadFull(log logr.Logger, r *http.Request) {
	fmt.Printf(
		"%s %s %s%s\n",
		o.au.Blue(r.Proto),
		o.au.Green(r.Method),
		o.au.Cyan(r.Host),
		o.au.Cyan(r.URL.String()), // unless the request is in the weird proxy form or whatever, this will only contain a path; scheme, host etc will be empty
	)
	for k, v := range r.Header {
		fmt.Printf("%s = %v\n", k, strings.Join(v, ","))
	}
}
func (o tty) HeadSummary(log logr.Logger, proto, method, path, ua string) {
	fmt.Printf(
		"%s %s %s by %s\n",
		o.au.Blue(proto),
		o.au.Green(method),
		o.au.Cyan(path),
		o.au.Cyan(ua),
	)
}
func (o tty) BodyFull(log logr.Logger, contentType string, r *http.Request, bs string) {
	fmt.Printf(
		"%s %d bytes of %s \n",
		o.au.Red("=>"),
		o.au.Cyan(r.ContentLength),
		o.au.Cyan(contentType),
	)
	fmt.Printf("%v", string(bs)) // assumes utf8
	fmt.Println()
}
func (o tty) BodySummary(log logr.Logger, contentType string, contentLength int64, bs string) {
	bodyLen := len(bs)
	printLen := min(bodyLen, 72)

	fmt.Printf(
		"%s %d bytes of %s \n",
		o.au.Red("=>"),
		o.au.Cyan(contentLength),
		o.au.Cyan(contentType),
	)
	fmt.Printf("%v", string(bs[0:printLen])) // assumes utf8
	if bodyLen > printLen {
		fmt.Printf("<%d bytes elided>", len(bs)-printLen)
	}
	fmt.Println()
}
