package output

import (
	"net/url"
	"testing"

	"github.com/logrusorgru/aurora/v3"
)

func TestUrlPath(t *testing.T) {
	tests := []struct {
		ip string
		op string
	}{
		{"https://example.com", "/"},
		{"https://example.com/", "/"},
		{"https://example.com/foo/bar", "/foo/bar"},
		{"https://example.com/foo/bar/", "/foo/bar/"},
		{"https://example.com/foo/bar?lol", "/foo/bar?lol"},
		{"https://example.com/foo/bar/?lol", "/foo/bar/?lol"},
		{"https://example.com/?lol", "/?lol"},
		{"https://example.com?lol", "/?lol"},
		{"https://example.com/foo/bar?lol=rofl", "/foo/bar?lol=rofl"},
		{"https://example.com/foo/bar?lol=rofl#one", "/foo/bar?lol=rofl#one"},
		{"https://example.com/foo/bar#one", "/foo/bar#one"},
		{"https://example.com/#one", "/#one"},
		{"https://example.com#one", "/#one"},
	}

	// Give this a no-color aurora that won't add any escape codes; we're just testing string construction, not colorization
	s := NewStyler(aurora.NewAurora(false))

	for _, test := range tests {
		url, _ := url.Parse(test.ip)
		res := s.UrlPath(url)
		if res != test.op {
			t.Errorf("Wrong answer; want: %s, got: %s", test.op, res)
		}
	}
}
