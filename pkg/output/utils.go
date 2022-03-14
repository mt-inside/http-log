package output

import (
	"crypto/tls"
	"fmt"
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

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
