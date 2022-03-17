package output

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/logrusorgru/aurora/v3"
	"github.com/mt-inside/http-log/pkg/utils"
)

type Styler struct {
	au aurora.Aurora

	InfoStyle   aurora.Color
	FailStyle   aurora.Color
	OkStyle     aurora.Color
	WarnStyle   aurora.Color
	AddrStyle   aurora.Color
	VerbStyle   aurora.Color
	NounStyle   aurora.Color
	BrightStyle aurora.Color
}

func NewStyler(au aurora.Aurora) Styler {
	return Styler{
		au:          au,
		InfoStyle:   aurora.BlackFg | aurora.BrightFg,
		FailStyle:   aurora.RedFg,
		OkStyle:     aurora.GreenFg,
		WarnStyle:   aurora.YellowFg,
		AddrStyle:   aurora.BlueFg,
		VerbStyle:   aurora.MagentaFg,
		NounStyle:   aurora.CyanFg,
		BrightStyle: aurora.WhiteFg | aurora.BrightFg,
	}
}

func (s Styler) Info(str string) aurora.Value {
	return s.au.Colorize(str, s.InfoStyle)
}
func (s Styler) Fail(str string) aurora.Value {
	return s.au.Colorize(str, s.FailStyle)
}
func (s Styler) Ok(str string) aurora.Value {
	return s.au.Colorize(str, s.OkStyle)
}
func (s Styler) Warn(str string) aurora.Value {
	return s.au.Colorize(str, s.WarnStyle)
}
func (s Styler) Addr(str string) aurora.Value {
	return s.au.Colorize(str, s.AddrStyle)
}
func (s Styler) Verb(str string) aurora.Value {
	return s.au.Colorize(str, s.VerbStyle)
}
func (s Styler) Noun(str string) aurora.Value {
	return s.au.Colorize(str, s.NounStyle)
}
func (s Styler) Bright(v interface{}) aurora.Value {
	return s.au.Colorize(v, s.BrightStyle)
}

func (s Styler) UrlPath(u *url.URL) string {
	var b strings.Builder

	if len(u.EscapedPath()) > 0 {
		b.WriteString(s.Noun(u.EscapedPath()).String())
	} else {
		b.WriteString(s.Noun("/").String())
	}

	if len(u.RawQuery) > 0 {
		b.WriteString("?")
		b.WriteString(s.Verb(u.RawQuery).String())
	}

	if len(u.EscapedFragment()) > 0 {
		b.WriteString("#")
		b.WriteString(s.Addr(u.EscapedFragment()).String())
	}

	return b.String()
}

func (s Styler) JWTClaims(token *jwt.Token) string {
	var b strings.Builder

	claims := token.Claims.(*jwt.RegisteredClaims)

	b.WriteString("[")
	start := claims.IssuedAt
	if claims.NotBefore != nil {
		start = claims.NotBefore
	}
	if start != nil {
		b.WriteString(utils.RenderTime(start.Time, true).String()) // TODO RenderTime should be in here cause it's really ColorizeTime
	} else {
		b.WriteString(s.Fail("?").String())
	}
	b.WriteString(" -> ")
	if claims.ExpiresAt != nil {
		b.WriteString(utils.RenderTime(claims.ExpiresAt.Time, false).String())
	} else {
		b.WriteString(s.Fail("?").String())
	}
	b.WriteString("]")

	if claims.ID != "" {
		fmt.Fprintf(&b, " id %s", s.Bright(claims.ID))
	}

	if claims.Subject != "" {
		fmt.Fprintf(&b, " subj %s", s.Noun(claims.Subject))
	}

	if claims.Issuer != "" {
		fmt.Fprintf(&b, " iss %s", s.Noun(claims.Issuer))
	}

	if len(claims.Audience) != 0 {
		fmt.Fprintf(&b, " aud %v", claims.Audience) // TODO: dat list colorizer
	}

	return b.String()
}

func (s Styler) JWTMeta(token *jwt.Token) string {
	var b strings.Builder

	switch method := token.Method.(type) {
	case *jwt.SigningMethodHMAC:
		fmt.Fprintf(&b, "signature %s (hash %s)", s.Noun(method.Name), s.Noun(method.Hash.String()))
	case *jwt.SigningMethodRSA:
		fmt.Fprintf(&b, "signature %s (hash %s)", s.Noun(method.Name), s.Noun(method.Hash.String()))
	case *jwt.SigningMethodRSAPSS:
		fmt.Fprintf(&b, "signature %s (hash %s)", s.Noun(method.Name), s.Noun(method.Hash.String()))
	case *jwt.SigningMethodECDSA:
		fmt.Fprintf(&b, "signature %s (hash %s)", s.Noun(method.Name), s.Noun(method.Hash.String())) // .CurveBits is in the name, .KeySize is that in bytes
	case *jwt.SigningMethodEd25519:
		fmt.Fprintf(&b, "signature %s", s.Noun(method.Alg()))
	}

	// token.Signature is filled in if we give the jwt parser a key to validate with, but it's opaque anyway

	return b.String()
}
