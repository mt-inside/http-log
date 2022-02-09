package output

import "crypto/tls"

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

var tlsVersionName = map[uint16]string{
	tls.VersionTLS10: "1.0",
	tls.VersionTLS11: "1.1",
	tls.VersionTLS12: "1.2",
	tls.VersionTLS13: "1.3",
}
