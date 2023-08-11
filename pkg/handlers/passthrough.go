package handlers

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mt-inside/http-log/pkg/state"
	"github.com/mt-inside/http-log/pkg/utils"
)

// TODO: can we rebase this onto https://pkg.go.dev/net/http/httputil@master#ReverseProxy
// - go 1.20 will add a new Rewrite hook with even more power
var perReqHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

type passthroughHandler struct {
	url        *url.URL
	daemonData *state.DaemonData
	reqData    *state.RequestData
	respData   *state.ResponseData
}

func NewPassthroughHandler(
	url *url.URL,
	daemonData *state.DaemonData,
	reqData *state.RequestData,
	respData *state.ResponseData,
) http.Handler {
	return &passthroughHandler{url, daemonData, reqData, respData}
}

func (ph passthroughHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := &net.Dialer{}
				conn, err := dialer.DialContext(ctx, network, address)
				if err == nil {
					ph.respData.PassthroughLocalAddress = conn.LocalAddr()
					ph.respData.PassthroughRemoteAddress = conn.RemoteAddr()
				}
				return conn, err
			},
		},
	}

	// TODO: we re-use the request object, and its *new* values are what's getting logged (eg with xff set). Either
	// - change order of this vs loggingMiddleware (code looks correct to me)
	// - make a new req object (being sure to copy over everything relevant)

	/* Whither */

	/* A note on auto-forwarding / proxying: This mode is a bit dodgy. a) we're an open proxy, which can be dangerous. b) proxies are a /thing/, and configuring a proxy on a client has all kinds of effects. We just about support being an http "proxy" cause we just make a new request. However when a client wants to proxy to https, they use the CONNECT verb, expecting us to set up a tunnel and let them do the handshake, which we don't support. We could make the request they want, but we can't return anything to them cause they're expecting a raw TCP tunnel and to do a TLS handshake.
	* The non-proxy mode (based on Host header, not request line) might seem a bit sus, but it's basically what any nginx reverse proxy does. And there's a bunch of reasons why a client might want us to actually make the connection on their behalf.
	 */

	/* A note on usage: We give the user maximum flexibility, so in the case of designated target, we *don't* set the request's Host or SNI to that target (eg you could passthrough to an IP, and the user could set Host per request). This means that in the common case, you have to set the Host header on each request, as well as giving it as passthrough target */

	if ph.url != nil {
		/* Designated passthrough target */
		req.URL = ph.url
	} else {
		/* Auto-passthrough mode */
		if req.URL.Host != "" { // HTTP request line has a host in it (not looking at Host header)
			/* We're being used as a proper proxy */
			if req.Method != "CONNECT" {
				/* Proxying to HTTP, works ok */
				/* HTTP_PROXY set; Req URL http://... */
			} else {
				/* Proxying to HTTPS, doesn't work */
				/* HTTP_PROXY set; Req URL httpS://... */
				// TODO: maybe we should actually set up the tunnel - how complicated are the semantics of CONNECT? In this case, we can log the CONNECT headers and tunnel rx/tx byte counts I guess
				http.Error(w, "CONNECT tunneling not supported", http.StatusBadGateway)
				ph.respData.HttpHeaderTime = time.Now()
				ph.respData.HttpStatusCode = http.StatusBadGateway
				return
				// FIXME:
				// - run: go run ./cmd/http-log -P -R -M
				// - and: /usr/bin/curl --proxy http://localhost:8080  https://openbsd.org
				// - notice how our logs contain OLD lines, like the response body stuff. How does that respData object even end up getting re-used??
				// - shit it's just getting re-used every time, don't do this. Need to think hard about handling errors, eg how to render a half-filled-out object. Detect zero-values and don't render them? Bool to mark sections of the flow as complete? Field for an error message to denote and explain an early exit (to be rendered in the log)? Ditto a warning message to be rendered (eg "don't call me like that")?
			}
		} else {
			/* We're not being used as "proper" proxy. This is basically what an nginx reverse proxy would do. */
			/* HTTP_PROXY UNset */
			/* HTTP/1.1 says Host must be set, so use that.
			* Note that if the user hasn't overridden it, it'll be set to whatever URL they used to call us, meaning we'll try to call ourself, and probably infinite loop?
			* TODO: try to detect this and kill it (http-logs might be chained, so looking for our own user agent in Via won't cut it. Mint an instance UUID at startup and put in x-http-log-instance header?)
			 */
			req.URL.Scheme = "https"
			if req.Header.Get("x-scheme") != "" {
				req.URL.Scheme = req.Header.Get("x-scheme")
			}
			// TODO: support connecting to custom ports too (x-port)
			req.URL.Host = req.Host
		}
	}
	// TODO: is it an issue that LoggMiddle's read the body already? Test with a request body from the original client
	ph.respData.PassthroughURL = req.URL

	/* Clear non-forward headers */

	req.RequestURI = "" // Can't be set on client requests

	for h := range perReqHeaders {
		req.Header.Del(h)
	}

	/* Add to xff */

	xff := req.Header.Get("x-forwarded-for")
	if xff != "" {
		xff += ", " // A note on the space: this is one header value which is manipulated, not several values that have been "folded"
	}
	xff += ph.reqData.TransportRemoteAddress.String()
	req.Header.Set("x-forwarded-for", xff)

	/* Add to Forwarded */

	// Forwaded: by=<incoming interface>;for=<caller>;host=<host it was looking for>;proto=<http|https>,...
	fwd := req.Header.Get("forwarded")
	if fwd != "" {
		fwd += ","
	}
	fwds := []string{
		"by=" + ph.reqData.TransportLocalAddress.String(),
		"for=" + ph.reqData.TransportRemoteAddress.String(),
		"host=" + ph.reqData.HttpHost,
		"proto=" + ph.daemonData.ServingProtocol(),
	}
	fwd += strings.Join(fwds, ";")
	req.Header.Set("forwarded", fwd)

	/* Add to Via */

	// TODO: should this be set by forward proxies?
	// Via: HTTP/1.1 proxy.foo.com:8080, <repeat>
	// Via: 1.1 proxy.foo.com, <repeat> (proxy's name)
	via := req.Header.Get("via")
	if via != "" {
		via += ", "
	}
	via += ph.reqData.HttpProtocolVersion + " " + utils.Hostname()
	req.Header.Set("via", via)

	/* Send */

	// TODO: also add Via and stuff (not least cause that contains this host's IP, rather than the apparent IP of the caller, which can be mis-leading
	// TODO: we're currently running stealth; we should actually announce ourselves with xff etc as we're active at L7
	// see: https://gist.github.com/yowu/f7dc34bd4736a65ff28d
	// Also: calculate the hops array after we've done all this, ie the chain we print should include us and the upstream
	ph.respData.ProxyRequestTime = time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// TODO: need to print err into the log somehow - error msg field on respData?
		// - this goes hand-in-hand with not rendering unset fields, like body time and bytes
		// - good test-case is cold-boot http-log, then get it to forward to https with invalid cert
		http.Error(w, fmt.Sprintf("Error forwarding request: %v", err), http.StatusBadGateway)
		ph.respData.HttpHeaderTime = time.Now()
		ph.respData.HttpStatusCode = http.StatusBadGateway
		return
	}
	defer resp.Body.Close()

	/* == Forward response == */

	/* Headers */

	for k, vs := range resp.Header {
		if perReqHeaders[k] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	/* Add to Via */

	// Via: HTTP/1.1 proxy.foo.com:8080, <repeat>
	// Via: 1.1 proxy.foo.com, <repeat> (proxy's name)
	respVia := resp.Header.Get("via")
	if respVia != "" {
		respVia += ", "
	}
	respVia += ph.reqData.HttpProtocolVersion + " " + utils.Hostname()
	w.Header().Set("via", respVia)
	// TODO: should any other forwarded-style headers be set by reverse proxies?

	/* Status */

	w.WriteHeader(resp.StatusCode)
	ph.respData.HttpHeaderTime = time.Now()
	ph.respData.HttpStatusCode = resp.StatusCode

	/* Body */

	n, _ := io.Copy(w, resp.Body) // Nothing we can really do about these errors cause the headers have been send. Client has to detect them from diff content-length vs body read
	ph.respData.HttpBodyTime = time.Now()
	ph.respData.HttpContentLength = resp.ContentLength
	ph.respData.HttpContentType = resp.Header.Get("Content-Type")
	ph.respData.HttpBodyLen = n
	// TODO: do an op if n != content-length header. Don't bail out though - best effort is what we want for this
}
