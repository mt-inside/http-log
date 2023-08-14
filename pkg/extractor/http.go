package extractor

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/mt-inside/http-log/pkg/state"
)

func HttpRequest(r *http.Request, srvData *state.DaemonData, d *state.RequestData) {
	d.HttpRequestTime = time.Now()
	d.HttpProtocolVersion = fmt.Sprintf("%d.%d", r.ProtoMajor, r.ProtoMinor)
	d.HttpMethod = r.Method

	// Store the unescaped (ie no %XX) values
	// - this means they can just be used when rendering them as strings; yes they're unescaped, but that's URL-encoding for use in HTTP; eg any '&' in query parts will still be html-element encoded
	// - if you want to parse the query you'll have to escape it again first, eg url.ParseQuery(url.EscapeQuery(foo))
	d.HttpPath = r.URL.Path                            // Store the unescaped (ie no %XX) path. FYI EscapedPath is garenteed-valid encoding of the Path, preferred over RawPath which is user-supplied and might not be a valid code
	d.HttpQuery, _ = url.QueryUnescape(r.URL.RawQuery) // Have to manually ask for this to be unescaped; the only parsing done for us is into a full Vaules structure
	//b.WarnErr(err) // TODO
	d.HttpFragment = r.URL.Fragment // Ditto EscapedFragment

	d.HttpHeaders = r.Header // Has a Clone() method but we're only gonna read
	d.HttpHost = r.Host
	d.HttpUserAgent = r.Header.Get("User-Agent")

	// Build a map (so that we don't have to call Cookies() later, and for faster lookups than that).
	// I don't believe cookie names can be duplicated
	for _, c := range r.Cookies() {
		d.HttpCookies[c.Name] = c
	}

	d.HttpContentLength = r.ContentLength
	d.HttpContentType = r.Header.Get("Content-Type")
}
