package codec

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/request"
	"github.com/mt-inside/http-log/pkg/output"
)

func TryExtractJWT(b output.Bios, r *http.Request, validateKeyPath string) (token *jwt.Token, tokenErr error, found bool) {
	var keyFunc func(token *jwt.Token) (interface{}, error) = nil
	if validateKeyPath != "" {
		bytes, err := ioutil.ReadFile(validateKeyPath)
		b.CheckErr(err)

		publicKey, err := ParsePublicKey(bytes)
		b.CheckErr(err)

		keyFunc = func(token *jwt.Token) (interface{}, error) { return publicKey, err }
	}

	token, tokenErr = request.ParseFromRequest(
		r,
		request.OAuth2Extractor, // Looks for `Authorization: Bearer foo` or body field `access_token`
		keyFunc,
		request.WithClaims(&jwt.RegisteredClaims{}),
		request.WithParser(jwt.NewParser(jwt.WithoutClaimsValidation())),
	)

	// Ergonomics of the jwt library are bad
	found = tokenErr == nil || !strings.Contains(tokenErr.Error(), "no token present in request")

	return
}

func HeaderFromRequest(r *http.Request, key string) (value string) {
	value = ""

	hs := r.Header[http.CanonicalHeaderKey(key)]
	if len(hs) >= 1 { // len(nil) == 0
		value = hs[0]
	}

	return
}
func HeaderFromMap(headers map[string]interface{}, key string) (value string) {
	value = ""
	if h, ok := headers[http.CanonicalHeaderKey(key)]; ok { // TODO we canonicalise the header key, but I don't think they're canonicalised in this map
		value = h.(string)
	}
	return
}

func JWT(token *jwt.Token) (start, end *time.Time, ID, subject, issuer string, audience []string, sigAlgo, hashAlgo string) {
	claims := token.Claims.(*jwt.RegisteredClaims)

	s := claims.IssuedAt
	if claims.NotBefore != nil {
		s = claims.NotBefore
	}
	start = nil
	if s != nil {
		start = &s.Time
	}

	end = nil
	if claims.ExpiresAt != nil {
		end = &claims.ExpiresAt.Time
	}

	ID = claims.ID

	subject = claims.Subject

	issuer = claims.Issuer

	audience = claims.Audience

	switch method := token.Method.(type) {
	case *jwt.SigningMethodHMAC:
		sigAlgo = method.Name
		hashAlgo = method.Hash.String()
	case *jwt.SigningMethodRSA:
		sigAlgo = method.Name
		hashAlgo = method.Hash.String()
	case *jwt.SigningMethodRSAPSS:
		sigAlgo = method.Name
		hashAlgo = method.Hash.String()
	case *jwt.SigningMethodECDSA:
		sigAlgo = method.Name
		hashAlgo = method.Hash.String()
		// .CurveBits is in the name, .KeySize is that in bytes
	case *jwt.SigningMethodEd25519:
		sigAlgo = method.Alg()
		hashAlgo = "?"
	}

	// token.Signature is filled in if we give the jwt parser a key to validate with, but it's opaque anyway

	return
}

func ParsePublicKey(key []byte) (crypto.PublicKey, error) {

	var err error

	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("File does not contain PEM-encoded data")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	return parsedKey, nil
}
