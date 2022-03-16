package output

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
)

// TODO will be in stdlib anytime now... https://go-review.googlesource.com/c/go/+/321733/, https://github.com/golang/go/issues/46308
func tlsVersionName(tlsVersion uint16) string {
	switch tlsVersion {
	// Deprecated; causes lint error
	// case tls.VersionSSL30:
	// 	return "SSLv3"
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04X", tlsVersion)
	}
}

func renderTLSVersionNames(vs []uint16) []string {
	var ss []string

	for _, v := range vs {
		ss = append(ss, tlsVersionName(v))
	}

	return ss
}

func renderCipherSuiteNames(cs []uint16) []string {
	var ss []string

	for _, c := range cs {
		ss = append(ss, tls.CipherSuiteName(c))
	}

	return ss
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func renderPathComponents(u *url.URL) string {
	var b strings.Builder

	if len(u.EscapedPath()) > 0 {
		b.WriteString(u.EscapedPath())
	} else {
		b.WriteString("/")
	}

	if len(u.RawQuery) > 0 {
		b.WriteString("?")
		b.WriteString(u.RawQuery)
	}

	if len(u.EscapedFragment()) > 0 {
		b.WriteString("#")
		b.WriteString(u.EscapedFragment())
	}

	return b.String()
}

func renderPathComponentsColor(u *url.URL, s Styler) string {
	var b strings.Builder

	if len(u.EscapedPath()) > 0 {
		b.WriteString(s.Noun(u.EscapedPath()).String())
	} else {
		b.WriteString(s.Noun("/").String())
	}

	if len(u.RawQuery) > 0 {
		b.WriteString("?")
		b.WriteString(s.Verb(u.RawQuery).String())
	}

	if len(u.EscapedFragment()) > 0 {
		b.WriteString("#")
		b.WriteString(s.Addr(u.EscapedFragment()).String())
	}

	return b.String()
}
