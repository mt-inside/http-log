package output

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"net"
)

func ZipHostsPort(hosts []string, port string) (ret []string) {
	for _, host := range hosts {
		ret = append(ret, net.JoinHostPort(host, port))
	}
	return
}

func PublicKeyInfo(key crypto.PublicKey) string {
	// Note on the comments: although this is renderPUBLICkey, we wanna print the private key size cause that's what matters, so try to derive it from what we've got
	switch pubKey := key.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA:%d", pubKey.Size()*8) // private and public are same; it's the length of the shared modulus
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA:%s", pubKey.Params().Name) // private and public are same; it's a fundamental property of the curve, implied by the curve name. That's /technically/ the curve size (whatever that means)
	case ed25519.PublicKey:
		return fmt.Sprintf("Ed25519(%d)", ed25519.PrivateKeySize*8) // Constant size
	case *ecdh.PrivateKey:
		return fmt.Sprintf("ECDH:%s", pubKey.Curve())
	default:
		return "<unknown public key type>"
	}
}
