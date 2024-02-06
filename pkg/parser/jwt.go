package parser

import (
	"context"
	"crypto"
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	jwtRequest "github.com/golang-jwt/jwt/v5/request"
)

/* This jwt library is bullshit.
* - Parse[WithClaims]() has a weird control flow and will check for semantic validity but then overwrite (not wrap) that error with a signature validation error unless you provide a key that actually validates it
*   - no tricks like a nil keyFunc or a keyFunc that returns nil or anything can avoid that error overwrite flow
*   - token.Valid doesn't help because it's set iff the *signature* is valid, so it's basically the same as the return value (it's never set by ParseUnverified)
*   - so if you don't have a real validation key you have to use ParseUnverified()
* - however ParseUnverified() skips signature validation but also Claims validation (eg expiry check)
*   - but the Claims' validation function is public so we can just call it ourself afterwards
 */

/* Note: this is technically an extractor and a parser (expander), as it has to do both in lockstep.
* If you want to be really pedantic, extract all the _possible_ keys into an array, inc "" where they weren't present, then expand later */

// ExtractAndParseJWT returns a JWT if one exists at all, else nil.
// If one exists, any issues with it are documented in tokenErr
func JWT(ctx context.Context, r *http.Request, validateKey crypto.PublicKey) (token *jwt.Token, tokenErr error) {

	es := []jwtRequest.Extractor{
		jwtRequest.AuthorizationHeaderExtractor, // Looks for `Authorization: Bearer foo`, strips the `Bearer`
	}

	for _, e := range es {
		// Call extraction manually, because if we use jwtRequest.ParseFromRequest() we can't ParseUnverified()
		var str string
		// fmt.Println("Looking for JWT with", e) TODO: log at debug, ditto the rest of them
		str, tokenErr = e.ExtractToken(r) // Errors if no token found
		if tokenErr != nil {
			// Found nothing in the place we looked for a token (that might be a JWT). Keep looking
			//fmt.Println("No token there")
			continue
		}

		// Now try to parse it to see if it's a JWT (rather than some other kind of token, eg be a cloud access token for OIDC endpoints)

		parser := jwt.NewParser()

		if validateKey != nil {
			token, tokenErr = parser.ParseWithClaims(
				str,
				&jwt.RegisteredClaims{},
				func(token *jwt.Token) (interface{}, error) { return validateKey, nil },
			)
		} else {
			// We have no key to verify the signature, so we have to use this function (keyFunc can't be nil in the others).
			// This is a subset of Parse[WithClaims], which does not verify the signature (fine), but also doesn't validate the core claims.
			// The function to do that claims validation is private in the v5 API, with a comment saying it might be made public later (in v4 we could call it)
			token, _, tokenErr = parser.ParseUnverified(
				str,
				&jwt.RegisteredClaims{},
			)
			// TODO: validate the claims, when validation function is public
		}
		if errors.Is(tokenErr, jwt.ErrTokenMalformed) {
			// It's not a JWT in this location, keep looking in the others
			//fmt.Println("Token wasn't a JWT")
			token = nil // Kinda horrible, but we're ok with errors (like expired), so even in the presense of an error we still deref the token. Thus we need to nil the token out (this is checked for later) in the cases the token struct isn't valid
			continue
		}

		// If we're here it *is* a JWT, so we've found it (assume there's only one)
		// There may still be "parse" errors, but they're things like unknown signature algos or expired tokens, so we want to see them
		break
	}

	return
}

func JWTNoSignature(str string) (token *jwt.Token, tokenErr error) {
	parser := jwt.NewParser()

	// We have no key to verify the signature, so parse and verify *nothing* (our only option)
	token, _, tokenErr = parser.ParseUnverified(
		str,
		&jwt.MapClaims{},
	)

	// TODO: validate the claims, when validation function is public

	return
}
