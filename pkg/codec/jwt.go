package codec

import (
	"crypto"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	jwtRequest "github.com/golang-jwt/jwt/v4/request"
)

/* This jwt library is bullshit.
* - ParseUnverified() skips semantic validation (eg expiry check) as well as signature validation
* - but the Claims validation function is public so we can just call it ourself afterwards
* - Parse[WithClaims]() has a weird control flow and will check for semantic validity but then overwrite (not wrap) that error with a signature validation one unless you provide a key that actually validates it (no tricks like a nil keyFunc or a keyFunc that returns nil or anything can avoid that error overwrite flow)
* - token.Valid is set iff the *signature* is valid (though tbf ParseUnverified() skips semantic validation so when else would it be set?)
 */
type NoValidationKeyError struct{}

func (e NoValidationKeyError) Error() string {
	return "Signature not validated as no validation key. No other errors."
}

func TryExtractJWT(r *http.Request, validateKey crypto.PublicKey) (token *jwt.Token, tokenErr error, found bool) {

	// Do extraction manually, because if we use jwtRequest.ParseFromRequest() we can't ParseUnverified()
	str, err := jwtRequest.OAuth2Extractor.ExtractToken(r) // Looks for `Authorization: Bearer foo` or body field `access_token`
	if err != nil {
		return nil, nil, false
	}
	found = true

	parser := jwt.NewParser()

	if validateKey != nil {
		token, tokenErr = parser.ParseWithClaims(
			str,
			&jwt.RegisteredClaims{},
			func(token *jwt.Token) (interface{}, error) { return validateKey, nil },
		)
	} else {
		token, _, tokenErr = parser.ParseUnverified(
			str,
			&jwt.RegisteredClaims{},
		)
		if tokenErr == nil {
			tokenErr = token.Claims.Valid()
			if tokenErr == nil {
				tokenErr = NoValidationKeyError{}
			}
		}
	}

	return
}

func TryParseJWT(str string) (*jwt.Token, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(
		str,
		&jwt.RegisteredClaims{},
	)
	return token, err // token.Valid is NOT set cause that's "is the signature valid" (we parse unvalidated), not "does it parse"?
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
