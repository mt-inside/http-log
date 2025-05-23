package enricher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tetratelabs/telemetry"

	"github.com/mt-inside/go-jwks"

	"github.com/mt-inside/http-log/internal/build"
	"github.com/mt-inside/http-log/pkg/state"
	"github.com/mt-inside/http-log/pkg/utils"
)

// Recall:
// - "scope", [OAuth2] a permission to do a thing, like "read", "write", "foo_admin", requested by the client
//   - [OIDC only, not raw JWT-as-bearer token] recall: scopes are requests (from the client to the auth server) for sets of claims
//     - the ID Token (for consumption by the client) doesn't mention the requested scopes, but contains the claims resulting from those scopes
//     - the Access Token (for consumption by the IdP's org's APIs) does contain the scopes requested/granted. This token is often opaque to the client (eg not a JWT). The issuer's API can use those scopes for coarse-grained authz if they want, but there's probably some other mechanism too (other bearer permissions in the access token, UID that can be looked up in access db, etc)
//       - if the access token is client-readable (a JWT), there is a schema for that (including a first-class scopes field): https://datatracker.ietf.org/doc/html/rfc9068
//   - OIDC standard scopes (and their claims):
//     - email: email, email_verified
//     - address: address
//     - profile: name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, updated_at
//     - phone: phone_number, phone_number_verified
//     - openid: sub, auth_time, acr
// - "claim", [Oauth2] a piece of information about the user; the IdP is claiming that it's true, and if you trust them then it is
//   - standard claims: iss, sub, aud, iat, nbf, exp, jti
// OIDC, because it gives authN info via what's meant to be an authZ system, (ab)uses scopes to be permissions to get groups of claims (info) about the user (think of it as the client requesting permission to read certain data about the user, the user consenting during the SSO process, and then the client having authZ to go read it from the /userinfo endpoint)
// It pre-defines various scopes that give bundles of info about the user [https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims]
// - "openid" - TODO. Not defined by them, but used eg by Google to mean ?? sub + iss?
// - "profile" - name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, updated_at
// - "email" - email, email_verified
// - "address" - address
// - "phone" - phone_number, phone_number_verified
// these ^^, plus "sub", are the standard claims in OIDC, anything else has to be specifically and individually requested
// - "sub" is "Identifier for the End-User at the Issuer"; seems to be the IdP-specific DB ID

// TODO: Printer should spot well-know IdToken fields (email, name, etc) and print them.
// - Can't detect it's an IdToken per se (or even better model the claims as a struct) because all the claims are optional based on the grants, right?
// - But there are pre-defined scopes, naming bundles of claims, which we should look for
// - The OIDC disco doc tells you what claims it supports: full mode should print all of them, with empty values if that's the case. summary mode should pick out certain ones
// - see https://developer.okta.com/blog/2017/07/25/oidc-primer-part-1
// - good doc: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc

// TODO:
// - find disco endpoint as $iss/.well-known/openid-configuration (does this always work? Will for Google. Try with a k8s cluster)
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
// - Cookie::AccessToken, and weirdly the :auth header we get (is that just an Envoy decision? check other IAPs), is the api token for making more calls to the IDP, eg hitting /userinfo
//   - this is opaque to the IDP, but encodes/references the claims the user agreed to when logging in, meaning if you use it to hit /userinfo then you can only see what they auth'd
//
// TODO: what we should do
// - we didn't kick off the the auth flow, we're just downstream of an IAP that did. Infer that from the presence of IdToken (remember that non-OIDC will just have a JWT in :Auth, with permission claims)
//   - IdToken existing means it was an OIDC flow, print that
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

// TODO: move me to RequestData
func getCookie(d *state.RequestData, name string) string {
	if d.HttpCookies[name] != nil {
		return d.HttpCookies[name].Value
	}
	return ""
}

// Returns the first found instance
func getCookiePrefix(d *state.RequestData, prefix string) string {
	for name := range d.HttpCookies {
		if strings.HasPrefix(name, prefix) {
			return getCookie(d, name)
		}
	}
	return ""
}

// TODO: shouldn't return the IdToken as token, it's authN / access token metadata; should build one from the userinfo, cause that's the authz info. Or probably add userinfo into it (return a map not a Token) - flow has to work for "proper" jwt bearer tokens too
func OIDCInfo(ctx context.Context, d *state.RequestData) (found bool, err error, token *jwt.Token, tokenErr error) {
	log := log.With(telemetry.KeyValuesFromContext(ctx)...)

	// Recall:
	// - access-token: whatever you need to access the cloud-provider's API on this user's behalf. Opaque - might be a JWT, might not
	// - id-token: oidc thing, jwt - info about the user that got authN'd.
	//   - oidc says this only has to contain authN info - what's their `sub` (again opaque), in addition to which IdP auth'd them, what's the aud, etc
	//   - may also contain info about the user you could use for authz, like their name and email.
	//     - or you may have to go get/augment that from the /userinfo endpoint (auth'ing with the access token)
	// These can all arrive in any number of places. Worse, since access-tokens are opaque, they can't be recognised
	// - eg
	//   - old / upstream EG
	//     - access-token: header Authorization Bearer
	//     - id-token: cookie IdToken
	//   - new EG / TEG
	//     - access-token: cookie BearerToken-foo
	//     - id-token: cookie IdToken-foo
	//   - istio-eco/authservice (example config)
	//     - access-token: header x-access-token
	//     - id-token: header Authorization Bearer

	if ctx.Err() != nil {
		log.Info("Not fetching any OIDC info", "reason", ctx.Err())
		return false, ctx.Err(), nil, nil
	}

	// ===
	// Find access and id-tokens
	// - we try common locations
	// - TODO: make both user-config, eg --oidc-access-token=header:Access-Token --oidc-id-token=cookie:IdToken
	// ===

	// Access token

	authBearer := ""
	authHeader := d.HttpHeaders.Get("Authorization")
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
		log.Debug("Authorization header doesn't contain a bearer token")
	} else {
		authBearer = authHeaderParts[1]
	}

	// TODO: try x-access-token
	accessToken := authBearer
	if accessToken == "" {
		accessToken = getCookiePrefix(d, "BearerToken")
	}

	if accessToken == "" {
		log.Info("Can't find access token. Tried: header Authorization, cookie BearerToken")
		return false, nil, nil, nil
	}
	log.Debug("Extracted access token", "token", accessToken)

	// ID token

	idToken := getCookiePrefix(d, "IdToken")
	if idToken == "" {
		idToken = d.HttpHeaders.Get("X-Id-Token")
	}

	if idToken == "" {
		log.Info("Can't find ID token. Tried: cookie IdToken, header X-Id-Token")
		return false, nil, nil, nil
	}
	log.Debug("Extracted ID token", "token", idToken)

	// ===
	// First parse
	// ===

	parser := jwt.NewParser()

	token, _, err = parser.ParseUnverified(
		idToken,
		&jwt.MapClaims{},
	)

	if errors.Is(err, jwt.ErrTokenMalformed) {
		return false, nil, nil, err
	}

	// IdToken == OIDC
	// TODO: think about control flow. Can't be returning true with invlaid/nil token. But also want what token info we can get even all the complicated io below fails.
	// TODO: proposal. Put the disco/userinfo/jwks stuff in a fn, call it with a deadline. If it timesout or errors, it just doesn't return a jwks/extra userinfo/etc, and we take the ParseUnverified path just like jwt.go

	// TODO: validate the claims, when validation function is public

	// ===
	// Discovery Document
	// ===

	oidcIdP, err := token.Claims.GetIssuer()
	if err != nil {
		log.Error("can't get issuer from token", err)
		return true, nil, token, err
	}
	oidcDiscoURI, err := url.JoinPath(oidcIdP, "/.well-known/openid-configuration")
	if err != nil {
		log.Error("can't form path for OIDC discovery document", err)
		return true, err, token, nil
	}
	oidcClient := &http.Client{}
	oidcDiscoRequest, err := http.NewRequestWithContext(ctx, "GET", oidcDiscoURI, nil)
	if err != nil {
		log.Error("can't construct HTTP request for OIDC Discovery Document", err)
		return true, err, token, nil
	}
	oidcDiscoRequest.Header.Set("User-Agent", build.NameAndVersion())
	oidcDiscoRequest.Header.Set("Authorization", "Bearer "+accessToken)
	log.Info("Fetching OIDC Discovery Document", "url", oidcDiscoURI)
	oidcDiscoResp, err := oidcClient.Do(oidcDiscoRequest)
	if err != nil {
		log.Error("can't fetch OIDC Discovery Docment", err)
		return true, err, token, nil
	}
	defer oidcDiscoResp.Body.Close()
	log.Info("Fetched OIDC Discovery Document", "status", oidcDiscoResp.Status)

	if !(oidcDiscoResp.StatusCode >= 200 && oidcDiscoResp.StatusCode < 400) {
		err = fmt.Errorf("HTTP status: %s", oidcDiscoResp.Status)
		log.Error("can't fetch OIDC Discovery Document", err)
		return true, err, token, nil
	}

	oidcDisco := map[string]interface{}{} // TODO type this
	err = json.NewDecoder(oidcDiscoResp.Body).Decode(&oidcDisco)
	if err != nil {
		log.Error("can't decode OIDC Discovery Docment", err)
		return true, err, token, nil
	}
	d.AuthOIDCDiscoSupportedClaims = utils.MapAnyToString(oidcDisco["claims_supported"].([]any))
	d.AuthOIDCDiscoSupportedSigs = utils.MapAnyToString(oidcDisco["id_token_signing_alg_values_supported"].([]any))

	//pretty.Println(oidcDisco)

	// ===
	// Userinfo
	// ===

	oidcUserinfoRequest, err := http.NewRequestWithContext(ctx, "GET", oidcDisco["userinfo_endpoint"].(string), nil)
	if err != nil {
		log.Error("can't construct HTTP request for OIDC Userinfo", err)
		return true, err, token, nil
	}
	// TODO factor out with above
	oidcUserinfoRequest.Header.Set("User-Agent", build.NameAndVersion())
	oidcUserinfoRequest.Header.Set("Authorization", "Bearer "+accessToken)
	log.Info("Fetching OIDC Userinfo", "url", oidcUserinfoRequest.URL)
	oidcUserinfoResp, err := oidcClient.Do(oidcUserinfoRequest)
	if err != nil {
		log.Error("can't fetch OIDC Userinfo", err)
		return true, err, token, nil
	}
	defer oidcUserinfoResp.Body.Close()
	log.Info("Fetched OIDC Userinfo", "status", oidcUserinfoResp.Status)

	if oidcUserinfoResp.StatusCode >= 200 && oidcUserinfoResp.StatusCode < 400 {
		// TODO: deal with other possible userinfo type: JWT (indicated in mime), nested JWT (detected how?)
		oidcUserinfo := map[string]any{}
		err = json.NewDecoder(oidcUserinfoResp.Body).Decode(&oidcUserinfo)
		if err != nil {
			log.Error("can't decode OIDC Userinfo", err)
			return true, err, token, nil
		}

		d.AuthOIDCUserinfo = oidcUserinfo
	}

	// ===
	// Public Keys
	// ===

	oidcJWKSRequest, err := http.NewRequestWithContext(ctx, "GET", oidcDisco["jwks_uri"].(string), nil)
	if err != nil {
		log.Error("can't construct HTTP request for OIDC JWKS", err)
		return true, err, token, nil
	}
	// TODO factor out with above
	oidcJWKSRequest.Header.Set("User-Agent", build.NameAndVersion())
	oidcJWKSRequest.Header.Set("Authorization", "Bearer "+accessToken)
	log.Info("Fetching OIDC JWKS", "url", oidcJWKSRequest.URL)
	oidcJWKSResp, err := oidcClient.Do(oidcJWKSRequest)
	if err != nil {
		log.Error("can't fetch OIDC JWKS", err)
		return true, err, token, nil
	}
	defer oidcJWKSResp.Body.Close()
	log.Info("Fetched OIDC JWKS", "status", oidcJWKSResp.Status)

	jwksBytes, err := io.ReadAll(oidcJWKSResp.Body)
	if err != nil {
		log.Error("can't read OIDC JWKS response body", err)
		return true, err, token, nil
	}
	pubKeys, err := jwks.JWKS2KeysMap(jwksBytes)
	if err != nil {
		log.Error("can't decode OIDC JWKS", err)
		return true, err, token, nil
	}

	d.AuthOIDCJwks = pubKeys
	log.Info("Parsed JWKS", "keys", len(pubKeys))

	// ===
	// Re-parse now we have keys to verify with
	// ===

	token, err = parser.ParseWithClaims(
		idToken,
		&jwt.MapClaims{},
		func(token *jwt.Token) (interface{}, error) {
			kid := token.Header["kid"].(string)
			jwksKey, ok := pubKeys[kid]
			log.Info("Validaing JWT with JWKS key", "key_id", kid, "key_exists", ok)
			if !ok {
				return nil, fmt.Errorf("have JWKS key bundle but it doesn't contain JWT's kid %s", kid)
			}
			return jwksKey, nil
		},
	)

	return true, nil, token, err
}
