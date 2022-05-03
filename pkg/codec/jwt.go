package codec

import (
	"crypto"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	jwtRequest "github.com/golang-jwt/jwt/v4/request"
)

func TryExtractJWT(r *http.Request, validateKey crypto.PublicKey) (token *jwt.Token, tokenErr error, found bool) {
	var keyFunc func(token *jwt.Token) (interface{}, error) = nil
	if validateKey != nil {
		keyFunc = func(token *jwt.Token) (interface{}, error) { return validateKey, nil }
	}

	token, tokenErr = jwtRequest.ParseFromRequest(
		r,
		jwtRequest.OAuth2Extractor, // Looks for `Authorization: Bearer foo` or body field `access_token`
		keyFunc,
		jwtRequest.WithClaims(&jwt.RegisteredClaims{}),
		jwtRequest.WithParser(jwt.NewParser(jwt.WithoutClaimsValidation())),
	)

	// Ergonomics of the jwt library are bad
	found = tokenErr == nil || !strings.Contains(tokenErr.Error(), "no token present in request")
	if !found {
		// TODO: remove this eventually
		fmt.Println("DEBUG maybe blocklist this error ie count it as a token not found?", tokenErr)
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
