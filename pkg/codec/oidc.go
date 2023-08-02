package codec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mt-inside/pem2jwks/pkg/jwks"

	"github.com/mt-inside/http-log/pkg/state"
)

// TODO: shouldn't return the IdToken as token, it's authN / access token metadata; should build one from the userinfo, cause that's the authz info. Or probably add userinfo into it (return a map not a Token) - flow has to work for "proper" jwt bearer tokens too
func TryFetchOIDCInfo(d *state.RequestData) (found bool, token *jwt.Token, tokenErr error) {
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
	if err != nil {
		return
	}
	oidcDiscoURI, err := url.JoinPath(oidcIdP, "/.well-known/openid-configuration")
	if err != nil {
		return
	}
	oidcClient := &http.Client{}
	oidcDiscoRequest, err := http.NewRequestWithContext(context.Background(), "GET", oidcDiscoURI, nil) // TODO: timeout, configurable, keep cancel
	if err != nil {
		return
	}
	oidcDiscoRequest.Header.Set("User-Agent", "print-cert")                          // TODO from build info
	oidcDiscoRequest.Header.Set("Authorization", d.HttpHeaders.Get("Authorization")) // assuming it must be there since we've detected we're beind and OIDC flow
	// TODO: debug. Make a struct to pass around containing { s, b, log }
	fmt.Println("Fetching OIDC Discovery Document from", oidcDiscoURI)
	oidcDiscoResp, err := oidcClient.Do(oidcDiscoRequest)
	if err != nil {
		return
	}
	defer oidcDiscoResp.Body.Close()
	fmt.Println("Status", oidcDiscoResp.Status)

	oidcDisco := map[string]interface{}{} // TODO type this
	err = json.NewDecoder(oidcDiscoResp.Body).Decode(&oidcDisco)
	if err != nil {
		return
	}

	//pretty.Print(oidcDisco)

	// ===
	// Userinfo
	// ===

	oidcUserinfoRequest, err := http.NewRequestWithContext(context.Background(), "GET", oidcDisco["userinfo_endpoint"].(string), nil)
	if err != nil {
		return
	}
	// TODO factor out with above
	oidcUserinfoRequest.Header.Set("User-Agent", "print-cert")                          // TODO from build info
	oidcUserinfoRequest.Header.Set("Authorization", d.HttpHeaders.Get("Authorization")) // assuming it must be there since we've detected we're beind and OIDC flow
	fmt.Println("Fetching OIDC Userinfo from", oidcUserinfoRequest.URL)
	oidcUserinfoResp, err := oidcClient.Do(oidcUserinfoRequest)
	if err != nil {
		return
	}
	defer oidcUserinfoResp.Body.Close()
	fmt.Println("Status", oidcUserinfoResp.Status)

	// TODO: deal with other possible userinfo type: JWT (indicated in mime), nested JWT (detected how?)
	oidcUserinfo := map[string]string{} // TODO type this?
	err = json.NewDecoder(oidcUserinfoResp.Body).Decode(&oidcUserinfo)
	if err != nil {
		return
	}

	//pretty.Print(oidcUserinfo)
	//fmt.Println()

	// ===
	// Public Keys
	// ===

	oidcJWKSRequest, err := http.NewRequestWithContext(context.Background(), "GET", oidcDisco["jwks_uri"].(string), nil)
	if err != nil {
		return
	}
	// TODO factor out with above
	oidcJWKSRequest.Header.Set("User-Agent", "print-cert")                          // TODO from build info
	oidcJWKSRequest.Header.Set("Authorization", d.HttpHeaders.Get("Authorization")) // assuming it must be there since we've detected we're beind and OIDC flow
	fmt.Println("Fetching OIDC JWKS from", oidcJWKSRequest.URL)
	oidcJWKSResp, err := oidcClient.Do(oidcJWKSRequest)
	if err != nil {
		return
	}
	defer oidcJWKSResp.Body.Close()
	fmt.Println("Status", oidcJWKSResp.Status)

	jwksBytes, err := io.ReadAll(oidcJWKSResp.Body)
	if err != nil {
		return
	}
	pubKeys, err := jwks.JSON2PublicKeys(jwksBytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	d.AuthOIDCJwks = pubKeys
	fmt.Printf("Parsed %d keys\n", len(pubKeys))

	// ===
	// Re-parse now we have keys to verify with
	// ===

	token, tokenErr = parser.ParseWithClaims(
		cookie.Value,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			kid := token.Header["kid"].(string)
			jwksKey, ok := pubKeys[kid]
			if !ok {
				return nil, fmt.Errorf("have JWKS key bundle but it doesn't contain JWT's kid %s", kid)
			}
			fmt.Printf("Validating JWT with JWKS key %s\n", kid)
			return jwksKey, nil
		},
	)

	return
}
