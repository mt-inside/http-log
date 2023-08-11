package parser

/* Note: this is technically an extractor and a parser (expander), as it has to do both in lockstep.
* If you want to be really pedantic, extract all the _possible_ keys into an array, inc "" where they weren't present, then expand later */

import (
	"crypto"
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	jwtRequest "github.com/golang-jwt/jwt/v5/request"

	"github.com/mt-inside/http-log/pkg/output"
)

/* This jwt library is bullshit.
* - Parse[WithClaims]() has a weird control flow and will check for semantic validity but then overwrite (not wrap) that error with a signature validation error unless you provide a key that actually validates it
*   - no tricks like a nil keyFunc or a keyFunc that returns nil or anything can avoid that error overwrite flow
*   - token.Valid doesn't help because it's set iff the *signature* is valid, so it's basically the same as the return value (it's never set by ParseUnverified)
*   - so if you don't have a real validation key you have to use ParseUnverified()
* - however ParseUnverified() skips signature validation but also Claims validation (eg expiry check)
*   - but the Claims' validation function is public so we can just call it ourself afterwards
 */

// ExtractAndParseJWT returns a JWT if one exists at all, else nil.
// If one exists, any issues with it are documented in tokenErr
func JWT(b output.Bios, r *http.Request, validateKey crypto.PublicKey) (token *jwt.Token, tokenErr error) {

	// TODO: Printer should spot well-know IdToken fields (email, name, etc) and print them.
	// - Can't detect it's an IdToken per se (or even better model the claims as a struct) because all the claims are optional based on the grants, right?
	// - maybe just have the printer print all fields in Full mode?
	// - see https://developer.okta.com/blog/2017/07/25/oidc-primer-part-1
	// - good doc: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc
	// Recall:
	// - "scope", [OAuth2] a permission to do a thing, like "read", "write", "foo_admin", requested by the client
	// - "claim", [Oauth2] a piece of information about the user; the IdP is claiming that it's true, and if you trust them then it is
	// OIDC, because it gives authN info via what's meant to be an authZ system, (ab)uses scopes to be permissions to get groups of claims (info) about the user (think of it as the client requesting permission to read certain data about the user, the user consenting during the SSO process, and then the client having authZ to go read it from the /userinfo endpoint)
	// It pre-defines various scopes that give bundles of info about the user [https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims]
	// - "profile" - name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, updated_at
	// - "email" - email, email_verified
	// - "address" - address
	// - "phone" - phone_number, phone_number_verified
	// these ^^, plus "sub", are the standard claims in OIDC, anything else has to be specifically and individually requested
	// - "sub" is "Identifier for the End-User at the Issuer"; seems to be the IdP-specific DB ID

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

	// TODO: fetch validation key from OIDC Discovery endpoint?
	// - find disco endpoint as $iss/.well-known/openid-configuration (does this always work? Will for Google. Try with a k8s cluster)
	// - print some info about the disco doc
	// - jwks_url is in there
	// - use it to get the userinfo endpoint, hit that (with AccessToken from the cookie) print those data
	//   - these are NOT always the same as the IdToken (verified empirically with Google); the spec says that the official flow is authN request & response (including IdToken), then /userinfo request and response
	//   - because the access token is opaque, the IdToken is info about the authN process, eg the issuer of the access token, its subject and its audience
	//     - so you're getting an access token (which as to be IdP-specific, and thus probably opaque to you), and IdToken which is a rendering of the salient parts of its data (literally just the IDs, of the iss (a URL), the aud, and the sub (again an DB ID number))
	//   - the spec say the IdToken MAY contain extra claims (eg email, I guess as a shortcut) but doesn't have to, and seemingly usually won't
	//   - having this token means you know the user's authenticated (ie has a current, valid account on that IdP, who is prepared to authN them for you as an audience)
	//     - this might be enough, eg "has this user signed up for my website?", "is this user a current active employee"
	//   - you can then do authZ, ig based on the sub (ie their ID number, even though it's the IdP's ID for them, just use it as the key in your authZ db?)
	//   - or you can get more info about them by hitting /userinfo (and ofc you might to this to get their email and use that as authz key)
	//     - I guess if you wanted to do "native" authZ rather tha hitting an auth db, you'd define custom claims with your IdP (like "write") and use the userinfo response conaining them as the bearer token?
	//   - OIDC spec: userinfo response might be plain JSON, a JWT, or a nested JWT (mime will differentiate)
	//   - think: spec shows the RP (relying party; client) doing both the SSO flow then getting /userinfo
	//     - this is fine if it's a monolith; what about microservices behind an APIGW / IAP?
	//       - what does Ambassador / aws APIgw / gcloud IAP / spring gw / etc do?
	//     - It kinda makes sense for the gateway to do the first bit (up to the access & id tokens), and then the uservices to use that access token to get userinfo if they want it, do authZ based on the IdToken's sub if they want
	// - actually tres useful: https://developers.google.com/identity/openid-connect/openid-connect
	// - see also "optional endpoints" in https://connect2id.com/learn/openid-connect
	// - OIDC spec (all useful): https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
	//
	// OIDC and what seems to happen (write me up here, and have EN about oauth?)
	// - IAP will do the exchange, hit us with various things in place
	// - Cookie::IdToken is the thing you want, it's a JWT
	// - Cookie::AccessToken, and weirdly the :auth header we get, is the api token for making more calls to the IDP, eg hitting /userinfo
	//   - this is opaque to the IDP, but encodes/references the claims the user agreed to when logging in, meaning if you use it to hit /userinfo then you can only see what they auth'd
	//
	// TODO: what we should do
	// - we didn't kick off the the auth flow, we're just downstream of an IAP that did. Infer that from the presence of IdToken (remember that non-OIDC will just have a JWT in :Auth, with permission claims)
	//   - IdToken existing means it was an OIDC flow, print that
	// - get the disco docuemtn, print that (fetch URL, its return code)
	// - JWKS stuff
	// - fetch userinfo, print req/resp (fetch URL, return code)
	// - render
	// Note: this is now I/O; a network call. Kick of a goroutine to do it (which can then goroutine jwks and userinfo in parallel).
	// - Have a user-programmable timeout.
	// - Wait for completion / deadline before printing - output will come with the timestamps that things happened, just printed a few secs later
	//
	// EG:
	// IdToken detected, inferring we're behind an IAP
	//   AuthN info from IdToken: iss foo aud bar sub baz
	// Fetching OIDC disco doc from https://foo.com/.well-known(addr) status 200 OK(green)
	// Fetching JWKS bundle from https://foo.com/.well-known/keyz(addr) status 200 OK(green)
	//   JWT signature valid? ok
	// Fetching Userinfo doc from https://foo.com/.well-known/userinfo(addr) status 200 OK (green)
	//   Userinfo: email foo(noun) name "bar baz"(noun)
}

func JWTNoSignature(str string) (token *jwt.Token, tokenErr error) {
	parser := jwt.NewParser()

	// We have no key to verify the signature, so parse and verify *nothing* (our only option)
	token, _, tokenErr = parser.ParseUnverified(
		str,
		&jwt.RegisteredClaims{},
	)

	// TODO: validate the claims, when validation function is public

	return
}
