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

	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/state"
)

var hopHeaders = map[string]bool{
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

	req.RequestURI = "" // Can't be set on client requests
	if ph.url != nil {
		req.URL = ph.url
	}
	// TODO: is it an issue that LoggMiddle's read the body already? Test with a request body from the original client
	ph.respData.PassthroughURL = req.URL

	/* Clear non-forward headers */

	for h := range hopHeaders {
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
	via += ph.reqData.HttpProtocolVersion + " " + codec.Hostname()
	req.Header.Set("via", via)

	/* Send */

	// TODO: also add Via and stuff (not least cause that contains this host's IP, rather than the apparent IP of the caller, which can be mis-leading
	// TODO: we're currently running stealth; we should actually announce ourselves with xff etc as we're active at L7
	// see: https://gist.github.com/yowu/f7dc34bd4736a65ff28d
	// Also: calculate the hops array after we've done all this, ie the chain we print should include us and the upstream
	ph.respData.ProxyRequestTime = time.Now()
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error forwarding request: %v", err), http.StatusBadGateway)
		ph.respData.HttpHeaderTime = time.Now()
		ph.respData.HttpStatusCode = http.StatusBadGateway
		return
	}
	defer resp.Body.Close()

	/* == Forward response == */

	/* Headers */

	for k, vs := range resp.Header {
		if hopHeaders[k] {
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
	respVia += ph.reqData.HttpProtocolVersion + " " + codec.Hostname()
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
