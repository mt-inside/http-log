package output

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

func ZipHostsPort(hosts []string, port string) (ret []string) {
	for _, host := range hosts {
		ret = append(ret, net.JoinHostPort(host, port))
	}
	return
}

func Slice2Strings[T fmt.Stringer](ins []T) []string {
	var out []string
	for _, in := range ins {
		out = append(out, in.String())
	}
	return out
}
func TLSVersions2Strings(vs []uint16) []string {
	var out []string
	for _, v := range vs {
		out = append(out, TLSVersionName(v))
	}
	return out
}
func CipherSuites2Strings(cs []uint16) []string {
	var out []string
	for _, c := range cs {
		out = append(out, tls.CipherSuiteName(c))
	}
	return out
}

func PublicKeyInfo(pk crypto.PublicKey) string {
	// Note on the comments: although this is renderPUBLICkey, we wanna print the private key size cause that's what matters, so try to derive it from what we've got
	switch pubKey := pk.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA:%d", pubKey.Size()*8) // private and public are same; it's the length of the shared modulus
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA:%s", pubKey.Params().Name) // private and public are same; it's a fundamental property of the curve, implied by the curve name. That's /technically/ the curve size (whatever that means)
	case ed25519.PublicKey:
		return fmt.Sprintf("Ed25519(%d)", ed25519.PrivateKeySize*8) // Constant size
	default:
		panic(errors.New("bottom"))
	}
}

// TODO will be in stdlib anytime now... https://go-review.googlesource.com/c/go/+/321733/, https://github.com/golang/go/issues/46308
func TLSVersionName(tlsVersion uint16) string {
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
		return fmt.Sprintf("Unknown 0x%04X", tlsVersion)
	}
}
