package output

import (
	"crypto/tls"
	"errors"
)

// TODO will be in stdlib anytime now... https://go-review.googlesource.com/c/go/+/321733/, https://github.com/golang/go/issues/46308
func tlsVersionName(tlsVersion uint16) string {
	switch tlsVersion {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		panic(errors.New("Unknown TLS version"))
	}
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
