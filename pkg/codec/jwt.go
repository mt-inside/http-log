package codec

import (
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

type NoValidationKeyError struct{}

func (e NoValidationKeyError) Error() string {
	return "Signature not validated as no validation key. No other errors."
}

type cookieIdTokenExtractor struct{}

// impl jwtRequest.Extractor
func (e cookieIdTokenExtractor) ExtractToken(req *http.Request) (string, error) {
	idToken, err := req.Cookie("IdToken")
	if err != nil {
		return "", jwtRequest.ErrNoTokenInRequest
	}
	return idToken.Value, nil
}

// ExtractAndParseJWT returns a JWT if one exists at all, else nil.
// If one exists, any issues with it are documented in tokenErr
func ExtractAndParseJWT(r *http.Request, validateKey crypto.PublicKey) (token *jwt.Token, tokenErr error) {

	// TODO: Printer should spot well-know IdToken fields (email, name, etc) and print them.
	// - Can't detect it's an IdToken per se (or even better model the claims as a struct) because all the claims are optional based on the grants, right?
	// - maybe just have the printer print all fields in Full mode?
	// - see https://developer.okta.com/blog/2017/07/25/oidc-primer-part-1
	// - good doc: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc

	es := []jwtRequest.Extractor{
		jwtRequest.AuthorizationHeaderExtractor, // Looks for `Authorization: Bearer foo`, strips the `Bearer`
		cookieIdTokenExtractor{},
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
			if tokenErr == nil {
				tokenErr = NoValidationKeyError{}
			}
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

	// TODO: fetch validation key from OIDC Discovery endpoint?
	// - find disco endpoint as $iss/.well-known/openid-configuration (does this always work? Will for Google. Try with a k8s cluster)
	// - print some info about the disco doc
	// - jwks_url is in there
	// - use it to get the userinfo endpoint, hit that (with AccessToken from the cookie), print those data (NOT always the same as the IdToken, verified cause my IdToken didn't have picture but /userinfo gave it me)
	// - actually tres useful: https://developers.google.com/identity/openid-connect/openid-connect
	// - see also "optional endpoints" in https://connect2id.com/learn/openid-connect
	//
	// OIDC and what seems to happen (write me up here, and have EN about oauth?)
	// - IAP will do the exchange, hit us with various things in place
	// - Cookie::IdToken is the thing you want, it's a JWT
	// - Cookie::AccessToken, and weirdly the :auth header we get, is the api token for making more calls to the IDP, eg hitting /userinfo
	//   - this is opaque to the IDP, but encodes/references the claims the user agreed to when logging in, meaning if you use it to hit /userinfo then you can only see what they auth'd
}

func ParseJWTNoSignature(str string) (token *jwt.Token, tokenErr error) {
	parser := jwt.NewParser()

	// We have no key to verify the signature, so parse and verify *nothing* (our only option)
	token, _, tokenErr = parser.ParseUnverified(
		str,
		&jwt.RegisteredClaims{},
	)

	// TODO: validate the claims, when validation function is public

	return
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
