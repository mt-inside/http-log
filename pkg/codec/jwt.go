package codec

import (
	"crypto"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	jwtRequest "github.com/golang-jwt/jwt/v4/request"
)

/* This jwt library is bullshit.
* - Parse[WithClaims]() has a weird control flow and will check for semantic validity but then overwrite (not wrap) that error with a signature validation error unless you provide a key that actually validates it
*   - no tricks like a nil keyFunc or a keyFunc that returns nil or anything can avoid that error overwrite flow
*   - token.Valid doesn't help because it's set iff the *signature* is valid, so it's basically the same as the return value
*   - so if you don't have a real validation key you have to use ParseUnverified()
* - however ParseUnverified() skips signature validation but also Claims validation (eg expiry check)
*   - but the Claims' validation function is public so we can just call it ourself afterwards
 */
type NoValidationKeyError struct{}

func (e NoValidationKeyError) Error() string {
	return "Signature not validated as no validation key. No other errors."
}

// ExtractAndParseJWT returns a JWT if one exists at all, else nil.
// If one exists, any issues with it are documented in tokenErr
func ExtractAndParseJWT(r *http.Request, validateKey crypto.PublicKey) (token *jwt.Token, tokenErr error) {

	// Do extraction manually, because if we use jwtRequest.ParseFromRequest() we can't ParseUnverified()
	str, err := jwtRequest.OAuth2Extractor.ExtractToken(r) // Looks for `Authorization: Bearer foo` or body field `access_token`
	if err != nil {
		return nil, nil
	}

	// If one exists, parse

	parser := jwt.NewParser()

	if validateKey != nil {
		return parser.ParseWithClaims(
			str,
			&jwt.RegisteredClaims{},
			func(token *jwt.Token) (interface{}, error) { return validateKey, nil },
		)
	} else {
		// We have no key to verify the signature, so parse and verify *nothing* (our only option)
		token, _, tokenErr = parser.ParseUnverified(
			str,
			&jwt.RegisteredClaims{},
		)
		if tokenErr == nil {
			// If there are no parse errors, check if the Claims are valid (eg token is not expired)
			tokenErr = token.Claims.Valid()
			if tokenErr == nil {
				// If all the Claims are valid, return our own error type indicating that the signature's validity is unknowable, as we have no validation key
				tokenErr = NoValidationKeyError{} // TODO: don't really like this control flow (with the later checking of tokenErr against this type). Rather, the outputter should be given a bool saying whether there was a validation key and thus whether there would ever be signature errors
			}
		}
		return
	}
}

func ParseJWTNoSignature(str string) (token *jwt.Token, tokenErr error) {
	parser := jwt.NewParser()

	// We have no key to verify the signature, so parse and verify *nothing* (our only option)
	token, _, tokenErr = parser.ParseUnverified(
		str,
		&jwt.RegisteredClaims{},
	)
	if tokenErr == nil {
		// If there are no parse errors, check if the Claims are valid (eg token is not expired)
		tokenErr = token.Claims.Valid()
		// cf ExtractAndParseJWT: don't return our own error saying there was no key to validate the signature; we know
	}

	return token, tokenErr
}

func JWTSignatureInfo(token *jwt.Token) (sigAlgo, hashAlgo string) {

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

	return
}
