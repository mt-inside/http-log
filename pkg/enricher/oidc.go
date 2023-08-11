package enricher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kr/pretty"

	"github.com/mt-inside/go-jwks"

	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/state"
)

// TODO: shouldn't return the IdToken as token, it's authN / access token metadata; should build one from the userinfo, cause that's the authz info. Or probably add userinfo into it (return a map not a Token) - flow has to work for "proper" jwt bearer tokens too
func OIDCInfo(b output.Bios, d *state.RequestData) (found bool, token *jwt.Token, tokenErr error) {
	cookie := d.HttpCookies["IdToken"]
	if cookie == nil {
		return // found: false
	}

	// ===
	// First parse
	// ===

	parser := jwt.NewParser()

	token, _, tokenErr = parser.ParseUnverified(
		cookie.Value,
		&jwt.RegisteredClaims{},
	)

	if errors.Is(tokenErr, jwt.ErrTokenMalformed) {
		token = nil // Kinda horrible, but we're ok with errors (like expired), so even in the presense of an error we still deref the token. Thus we need to nil the token out (this is checked for later) in the cases the token struct isn't valid
		return      // found: false
	}

	// IdToken == OIDC
	found = true // TODO: think about control flow. Can't be returning true with invlaid/nil token. But also want what token info we can get even all the complicated io below fails.
	// TODO: proposal. Put the disco/userinfo/jwks stuff in a fn, call it with a deadline. If it timesout or errors, it just doesn't return a jwks/extra userinfo/etc, and we take the ParseUnverified path just like jwt.go

	// TODO: validate the claims, when validation function is public

	// ===
	// Discovery Document
	// ===

	// TODO: timeout of 0 means don't fetch this stuff at all (print as much)
	// default timeout thus say 10s?

	oidcIdP, err := token.Claims.GetIssuer()
	if b.CheckPrintErr(err) {
		return
	}
	oidcDiscoURI, err := url.JoinPath(oidcIdP, "/.well-known/openid-configuration")
	if b.CheckPrintErr(err) {
		return
	}
	oidcClient := &http.Client{}
	oidcDiscoRequest, err := http.NewRequestWithContext(context.Background(), "GET", oidcDiscoURI, nil) // TODO: timeout, configurable, keep cancel
	if b.CheckPrintErr(err) {
		return
	}
	oidcDiscoRequest.Header.Set("User-Agent", "http-log")                            // TODO from build info
	oidcDiscoRequest.Header.Set("Authorization", d.HttpHeaders.Get("Authorization")) // assuming it must be there since we've detected we're beind and OIDC flow
	// TODO: debug. Make a struct to pass around containing { s, b, log }
	b.TraceWithName("oidc", "Fetching OIDC Discovery Document", "url", oidcDiscoURI)
	oidcDiscoResp, err := oidcClient.Do(oidcDiscoRequest)
	if b.CheckPrintErr(err) {
		return
	}
	defer oidcDiscoResp.Body.Close()
	b.TraceWithName("oidc", "Fetched OIDC Discovery Document", "status", oidcDiscoResp.Status)

	oidcDisco := map[string]interface{}{} // TODO type this
	err = json.NewDecoder(oidcDiscoResp.Body).Decode(&oidcDisco)
	if b.CheckPrintErr(err) {
		return
	}

	//pretty.Println(oidcDisco)

	// ===
	// Userinfo
	// ===

	oidcUserinfoRequest, err := http.NewRequestWithContext(context.Background(), "GET", oidcDisco["userinfo_endpoint"].(string), nil)
	if b.CheckPrintErr(err) {
		return
	}
	// TODO factor out with above
	oidcUserinfoRequest.Header.Set("User-Agent", "http-log")                            // TODO from build info
	oidcUserinfoRequest.Header.Set("Authorization", d.HttpHeaders.Get("Authorization")) // assuming it must be there since we've detected we're beind and OIDC flow
	b.TraceWithName("oidc", "Fetching OIDC Userinfo", "url", oidcUserinfoRequest.URL)
	oidcUserinfoResp, err := oidcClient.Do(oidcUserinfoRequest)
	if b.CheckPrintErr(err) {
		return
	}
	defer oidcUserinfoResp.Body.Close()
	b.TraceWithName("oidc", "Fetched OIDC Userinfo", "status", oidcUserinfoResp.Status)

	if oidcUserinfoResp.StatusCode >= 200 && oidcUserinfoResp.StatusCode < 400 {
		// TODO: deal with other possible userinfo type: JWT (indicated in mime), nested JWT (detected how?)
		oidcUserinfo := map[string]string{} // TODO type this?
		err = json.NewDecoder(oidcUserinfoResp.Body).Decode(&oidcUserinfo)
		if b.CheckPrintErr(err) {
			return
		}

		pretty.Println(oidcUserinfo)
	}

	// ===
	// Public Keys
	// ===

	oidcJWKSRequest, err := http.NewRequestWithContext(context.Background(), "GET", oidcDisco["jwks_uri"].(string), nil)
	if b.CheckPrintErr(err) {
		return
	}
	// TODO factor out with above
	oidcJWKSRequest.Header.Set("User-Agent", "http-log")                            // TODO from build info
	oidcJWKSRequest.Header.Set("Authorization", d.HttpHeaders.Get("Authorization")) // assuming it must be there since we've detected we're beind and OIDC flow
	b.TraceWithName("oidc", "Fetching OIDC JWKS", "url", oidcJWKSRequest.URL)
	oidcJWKSResp, err := oidcClient.Do(oidcJWKSRequest)
	if b.CheckPrintErr(err) {
		return
	}
	defer oidcJWKSResp.Body.Close()
	b.TraceWithName("oidc", "Fetched OIDC JWKS", "status", oidcJWKSResp.Status)

	jwksBytes, err := io.ReadAll(oidcJWKSResp.Body)
	if b.CheckPrintErr(err) {
		return
	}
	pubKeys, err := jwks.JWKS2KeysMap(jwksBytes)
	if b.CheckPrintErr(err) {
		return
	}

	d.AuthOIDCJwks = pubKeys
	b.TraceWithName("oidc", "Parsed JWKS", "keys", len(pubKeys))

	// ===
	// Re-parse now we have keys to verify with
	// ===

	token, tokenErr = parser.ParseWithClaims(
		cookie.Value,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			kid := token.Header["kid"].(string)
			jwksKey, ok := pubKeys[kid]
			b.TraceWithName("oidc", "Validaing JWT with JWKS key", "key_id", kid, "key_exists", ok)
			if !ok {
				return nil, fmt.Errorf("have JWKS key bundle but it doesn't contain JWT's kid %s", kid)
			}
			return jwksKey, nil
		},
	)

	return
}
