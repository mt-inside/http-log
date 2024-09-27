package output

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/logrusorgru/aurora/v3"

	"github.com/mt-inside/http-log/pkg/utils"
)

type TtyStyler struct {
	au aurora.Aurora
}

const (
	printWidth = 80

	timeFmt = "2006 Jan _2 15:04:05"

	InfoStyle aurora.Color = aurora.BlackFg | aurora.BrightFg
	FailStyle aurora.Color = aurora.RedFg
	OkStyle   aurora.Color = aurora.GreenFg
	WarnStyle aurora.Color = aurora.YellowFg

	AddrStyle     aurora.Color = aurora.BlueFg
	VerbStyle     aurora.Color = aurora.MagentaFg
	NounStyle     aurora.Color = aurora.CyanFg
	NumberStyle   aurora.Color = aurora.CyanFg
	DurationStyle aurora.Color = aurora.BlueFg
	BrightStyle   aurora.Color = aurora.WhiteFg | aurora.BrightFg
)

func NewTtyStyler(au aurora.Aurora) TtyStyler {
	return TtyStyler{
		au: au,
	}
}

func (s TtyStyler) Info(v any) string {
	if len(fmt.Sprint(v)) == 0 {
		return s.Info("<none>")
	}
	return s.au.Colorize(v, InfoStyle).String()
}
func (s TtyStyler) Fail(v any) string {
	if len(fmt.Sprint(v)) == 0 {
		return s.Info("<none>")
	}
	return s.au.Colorize(v, FailStyle).String()
}
func (s TtyStyler) Ok(v any) string {
	if len(fmt.Sprint(v)) == 0 {
		return s.Info("<none>")
	}
	return s.au.Colorize(v, OkStyle).String()
}
func (s TtyStyler) Warn(v any) string {
	if len(fmt.Sprint(v)) == 0 {
		return s.Info("<none>")
	}
	return s.au.Colorize(v, WarnStyle).String()
}
func (s TtyStyler) Addr(v any) string {
	if len(fmt.Sprint(v)) == 0 {
		return s.Info("<none>")
	}
	return s.au.Colorize(v, AddrStyle).String()
}
func (s TtyStyler) Verb(v any) string {
	if len(fmt.Sprint(v)) == 0 {
		return s.Info("<none>")
	}
	return s.au.Colorize(v, VerbStyle).String()
}
func (s TtyStyler) Noun(v any) string {
	if len(fmt.Sprint(v)) == 0 {
		return s.Info("<none>")
	}
	return s.au.Colorize(v, NounStyle).String()
}
func (s TtyStyler) Number(v any) string {
	if len(fmt.Sprint(v)) == 0 {
		return s.Info("<none>")
	}
	return s.au.Colorize(v, NumberStyle).String()
}
func (s TtyStyler) Duration(v time.Duration) string {
	return s.au.Colorize(v, DurationStyle).String()
}
func (s TtyStyler) Bright(v any) string {
	if len(fmt.Sprint(v)) == 0 {
		return s.Info("<none>")
	}
	return s.au.Colorize(v, BrightStyle).String()
}

func (s TtyStyler) RenderOk(msg string) string {
	return fmt.Sprintf("%s %s", s.Ok("Ok"), msg)
}
func (s TtyStyler) RenderInfo(msg string) string {
	return fmt.Sprintf("%s %s", s.Info("Info"), msg)
}
func (s TtyStyler) RenderWarn(msg string) string {
	return fmt.Sprintf("%s %s", s.Warn("Warning"), msg)
}
func (s TtyStyler) RenderErr(msg string) string {
	return fmt.Sprintf("%s %s", s.Fail("Error"), msg)
}

func (s TtyStyler) Banner(msg string) string {
	return fmt.Sprintf("\n== %s ==\n\n", s.Bright(msg))
}

func (s TtyStyler) Url(u *url.URL) string {
	var b strings.Builder

	b.WriteString(s.Verb(u.Scheme))

	b.WriteString("://")

	// TODO: add delimiter. What even is this part?
	b.WriteString(u.Opaque)

	// TODO: add delimiter.
	b.WriteString(u.User.String())

	b.WriteString(s.Noun(u.Host))

	b.WriteString(s.UrlPath(u))

	return b.String()
}

func (s TtyStyler) UrlPath(u *url.URL) string {
	var b strings.Builder

	// TODO: should probably use the unescaped versions of these, ie u.Path, url.UnescapeQuery(u.RawQuery), u.Fragment
	if len(u.EscapedPath()) > 0 {
		b.WriteString(s.Addr(u.EscapedPath()))
	} else {
		b.WriteString(s.Addr("/"))
	}

	if len(u.RawQuery) > 0 {
		b.WriteString("?")
		b.WriteString(s.Verb(u.RawQuery))
	}

	if len(u.EscapedFragment()) > 0 {
		b.WriteString("#")
		b.WriteString(s.Addr(u.EscapedFragment()))
	}

	return b.String()
}
func (s TtyStyler) PathElements(path, query, fragment string) string {
	var b strings.Builder

	if len(path) > 0 {
		b.WriteString(s.Addr(path))
	} else {
		b.WriteString(s.Addr("/"))
	}

	if len(query) > 0 {
		b.WriteString("?")
		b.WriteString(s.Verb(query))
	}

	if len(fragment) > 0 {
		b.WriteString("#")
		b.WriteString(s.Addr(fragment))
	}

	return b.String()
}

type TimestampType uint32

const (
	TimestampNone TimestampType = iota
	TimestampAbsolute
	TimestampRelative
)

func (s TtyStyler) Timestamp(t time.Time, tsType TimestampType, start *time.Time) string {
	switch tsType {
	case TimestampNone:
		return ""
	case TimestampAbsolute:
		return s.Info(t.Format("15:04:05") + " ")
	case TimestampRelative:
		d := t.Sub(*start)
		return s.Info(d.String() + " ")
	default:
		panic("bottom")
	}
}

func (s TtyStyler) TimeOkExpired(t time.Time, start bool) string {
	if start {
		if t.After(time.Now()) {
			return s.Fail(t.Format(timeFmt))
		} else {
			return s.Ok(t.Format(timeFmt))
		}
	} else {
		if t.Before(time.Now()) {
			return s.Fail(t.Format(timeFmt))
		} else if t.Before(time.Now().Add(240 * time.Hour)) {
			return s.Warn(t.Format(timeFmt))
		} else {
			return s.Ok(t.Format(timeFmt))
		}
	}
}

func (s TtyStyler) YesNo(test bool) string {
	if test {
		return s.Ok("yes")
	}
	return s.Fail("no")
}
func (s TtyStyler) YesInfo(test bool) string {
	if test {
		return s.Ok("yes")
	}
	return s.Info("no")
}
func (s TtyStyler) YesError(err error) string {
	if err == nil {
		return s.Ok("yes")
	}
	return s.Fail("no: " + err.Error())
}
func (s TtyStyler) YesErrorWarning(err error, warning bool) string {
	if err == nil {
		return s.Ok("yes")
	}
	if warning {
		return s.Warn("no: " + err.Error())
	}
	return s.Fail("no: " + err.Error())
}

// TODO: fix: if str is styled, this chops off the styling end escape codes. Should panic if called with an styled string (search for the escape char). Really you want a diff type for styled strings to enforce this at compile time
// TODO: ofc all this Truncate (and printlen in List and Map) stuff is bollocks. You don't know what other chars/indent are on that line. Should be rendering everything into the indenter, which should (at final print time) chop every resulting line to a given width (ideally reading the terminal's width)
// - have a global --no-truncate option that applies here, to lists, etc (styler should be constructed over it).
func (s TtyStyler) Truncate(str string) string {
	l := len(str)
	if l > printWidth {
		return str[:printWidth] + "..."
	}
	return str
}

func (s TtyStyler) List(ins []string, style aurora.Color) string {
	if len(ins) == 0 {
		return s.au.Colorize("<none>", InfoStyle).String()
	}

	var b strings.Builder
	printLen := 0

	for i, in := range ins {
		newPrintLen := printLen + len(in) // without the escape sequences
		if newPrintLen > printWidth {
			b.WriteString(s.au.Colorize(in[:printWidth-printLen], style).String())
			b.WriteString("...")
			break
		}
		b.WriteString(s.au.Colorize(in, style).String())

		if i != len(ins)-1 {
			newPrintLen += len(", ")
			if newPrintLen > printWidth {
				break
			} else {
				b.WriteString(", ")
			}
		}

		printLen = newPrintLen
	}

	return b.String()
}

func (s TtyStyler) Map(ins map[string]any, style aurora.Color) string {
	if len(ins) == 0 {
		return s.au.Colorize("<none>", InfoStyle).String()
	}

	var b strings.Builder

	// TODO: printlen constraint

	for k, v := range ins {
		b.WriteString(k)
		b.WriteString(" ")
		b.WriteString(s.au.Colorize(v, style).String())
		b.WriteString(" ")
	}

	return b.String()
}

func (s TtyStyler) PublicKeySummary(key crypto.PublicKey) string {
	return s.Noun(PublicKeyInfo(key))
}

func (s TtyStyler) CertSummary(cert *x509.Certificate) string {
	caInfo := ""
	if cert.IsCA {
		caInfo += s.Ok("ca")
		caInfo += ", path len "
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			caInfo += s.Number(strconv.Itoa(cert.MaxPathLen))
		} else {
			caInfo += s.Info("unset")
		}
	} else {
		caInfo += s.Info("leaf")
	}

	return fmt.Sprintf(
		"[%s -> %s] %s %s sig %s [%s]",
		s.TimeOkExpired(cert.NotBefore, true),
		s.TimeOkExpired(cert.NotAfter, false),
		s.Addr(cert.Subject.String()),
		s.PublicKeySummary(cert.PublicKey),
		s.Noun(cert.SignatureAlgorithm.String()),
		// No need to print Issuer, cause that's the Subject of the next cert in the chain
		caInfo,
	)
}

func (s TtyStyler) Issuer(cert *x509.Certificate) string {
	if cert.Issuer.String() == cert.Subject.String() {
		return s.Info("<self-signed>")
	}
	return s.Addr(cert.Issuer.String())
}

func (s TtyStyler) certSansRenderer(cert *x509.Certificate) string {
	var b IndentingBuilder

	b.Printf("SANs:")
	anySans := false

	if len(cert.DNSNames) > 0 {
		b.Printf(" DNS %s", s.List(cert.DNSNames, AddrStyle))
		anySans = true
	}
	if len(cert.IPAddresses) > 0 {
		b.Printf(" IPs %s", s.List(utils.MapToString(cert.IPAddresses), AddrStyle))
		anySans = true
	}
	if len(cert.URIs) > 0 {
		b.Printf(" URIs %s", s.List(utils.Map(cert.URIs, s.Url), AddrStyle))
		anySans = true
	}
	if len(cert.EmailAddresses) > 0 {
		b.Printf(" Emails %s", s.List(cert.EmailAddresses, AddrStyle))
		anySans = true
	}

	if !anySans {
		b.Print(s.Info(" <none>"))
	}

	b.NewLine()

	return b.String()
}

// TODO DONE?: condense this and all the below into one function, with options to
// - print head cert details, or not, and do so as client/server cert - make the details printer funcs public and then the caller can call this with output.FooHeadRender as an arg
// - verify signature (implied by non-nil caCert
// - Print chain
// - Print SAN info (the only difference between ServingCertChain and ClientCertChain ?)
// - Verify an addr (parse as either ip or name) against the SANs & CN
// TODO: builder pattern (and verifiedCertChain)
func (s TtyStyler) certChain(chain, verificationPath []*x509.Certificate, systemRoots bool, headCb func(cert *x509.Certificate) string) string {
	var b IndentingBuilder

	head := chain[0]
	b.Linef("0: %s", s.CertSummary(head))
	if headCb != nil {
		b.Indent()
		b.Block(headCb(head))
		b.Dedent()
	}

	certs := verificationPath
	if certs == nil {
		certs = chain
	}

	for i := 1; i < len(certs); i++ {
		b.Tabs()
		b.Printf("%d: ", i)

		if verificationPath != nil && i >= len(chain) {
			if systemRoots {
				b.Print("INSTALLED ")
			} else {
				b.Print("PROVIDED ")
			}
		} else {
			// TODO: any of these might also be installed, would be great to print that too if it's true.
			// The only way I can think of to determine that is to try to validate chain[0:0], chain[0:1] etc until it validates, at which point you know 0<x<n were presented only, n<x<len(chain) were presented and installed, and len(chain)<x<len(verified) were installed only
			b.Print("PRESENTED ")
		}

		b.Printf("%s", s.CertSummary(certs[i]))
		b.NewLine()
	}

	b.Linef("%d: %s", len(certs), s.Issuer(certs[len(certs)-1]))

	return b.String()
}

func (s TtyStyler) ServingCertChain(chain []*x509.Certificate) string {
	return s.certChain(chain, nil, false, s.certSansRenderer)
}
func (s TtyStyler) ClientCertChain(chain []*x509.Certificate) string {
	return s.certChain(chain, nil, false, s.certSansRenderer) // Client certs sometimes use SANs rather than CN for the name, eg that's where Istio looks
}

func (s TtyStyler) verifiedCertChain(
	chain []*x509.Certificate,
	caCerts []*x509.Certificate,
	validateAddr string,
	validateUsage []x509.ExtKeyUsage,
	headCb func(cert *x509.Certificate) string,
	verbose bool,
) string {
	var b IndentingBuilder

	if len(chain) == 0 {
		b.Line("Cert chain empty")
		return b.String()
	}

	head := chain[0]

	opts := x509.VerifyOptions{
		// We could pass a `DNSName: foo` here, but that calls 1stCert.VerifyHostname(foo), which we do manually below
		Intermediates: x509.NewCertPool(),
		KeyUsages:     validateUsage,
	}
	for _, cert := range chain[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if len(caCerts) != 0 {
		opts.Roots = x509.NewCertPool()
		for _, caCert := range caCerts {
			opts.Roots.AddCert(caCert)
		}
	}
	// If no custom CA is given, leave opts.Roots nil, which uses system roots to verify. Ie can't give an _empty_ opts.Roots

	if verbose {
		if len(caCerts) == 0 {
			b.Line("Validating against system certs")
		}
		for _, caCert := range caCerts {
			b.Linef("Validating against: %s", s.CertSummary(caCert))
		}
		b.NewLine()
	}

	validChains, err := chain[0].Verify(opts)

	if err != nil {
		// Cert isn't valid: just print it and any chain it came with
		b.Block(s.certChain(chain, nil, false, headCb)) // TODO: print only the head cert in non-verbose mode (same in the other branch)
		b.NewLine()
	} else {
		// Cert is valid: print any and all paths to validation
		// TODO: something (styler) needs an "indent writer" that targets a Builder and has the indent/dedent functions. Generalises over what bios does (bios should defer to that and actually output)
		// - bios doesn't actually need it then; the binaries can just use it from styler and fmt.Print the result, bios can do the same
		// - NewLine method too
		b.Line("Validation chain(s):")
		b.Indent()
		for _, validChain := range validChains {
			b.Block(s.certChain(chain, validChain, len(caCerts) == 0, headCb))
			b.NewLine()
		}
		b.Dedent()
	}

	b.Linef("Cert valid? %s", s.YesError(err))

	if validateAddr != "" {
		if ip := net.ParseIP(validateAddr); ip != nil {
			validateAddr = "[" + ip.String() + "]"
		}
		b.Linef("Requested SNI (%s) in DNS/IP SANs? %s; in CN? %s",
			s.au.Colorize(validateAddr, AddrStyle),
			s.YesError(head.VerifyHostname(validateAddr)), // TODO: strip any port, and iff IP wrap in []
			s.YesInfo(strings.EqualFold(head.Subject.CommonName, validateAddr)),
		)
	}

	b.NewLine()

	return b.String()
}

func (s TtyStyler) VerifiedServingCertChain(chain []*x509.Certificate, caCerts []*x509.Certificate, validateAddr string, verbose bool) string {
	return s.verifiedCertChain(chain, caCerts, validateAddr, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, s.certSansRenderer, verbose)
}
func (s TtyStyler) VerifiedClientCertChain(chain []*x509.Certificate, caCert *x509.Certificate, verbose bool) string {
	return s.verifiedCertChain(chain, []*x509.Certificate{caCert}, "", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, s.certSansRenderer, verbose)
}

func (s TtyStyler) jwtCommon(token *jwt.Token) *IndentingBuilder {
	var b IndentingBuilder

	b.Print(s.Noun("JWT"))
	claims := token.Claims.(*jwt.MapClaims)

	/* Times */

	b.Print(" [")

	start, err := claims.GetNotBefore()
	if err != nil || start == nil {
		start, err = claims.GetIssuedAt()
		if err != nil || start == nil {
			b.Print(s.Fail("?"))
		}
	}
	if err == nil && start != nil {
		b.Print(s.TimeOkExpired(start.Time, true))
	}

	b.Print(" -> ")

	if expires, err := claims.GetExpirationTime(); err == nil && expires != nil {
		b.Print(s.TimeOkExpired(expires.Time, false))
	} else {
		b.Print(s.Fail("?"))
	}

	b.Print("]")

	/* Other claims */

	id := (*claims)["id"]
	if idStr, ok := id.(string); ok {
		b.Printf(" id %s", s.Bright(idStr))
	}

	if sub, err := claims.GetSubject(); err == nil {
		b.Printf(" subj %s", s.Addr(sub))
	}

	if iss, err := claims.GetIssuer(); err == nil {
		b.Printf(" iss %s", s.Addr(iss))
	}

	if auds, err := claims.GetAudience(); err == nil && len(auds) != 0 {
		b.Printf(" aud %s", s.List(auds, AddrStyle))
	}

	return &b
}

func (s TtyStyler) JWTSummary(token *jwt.Token) string {
	return s.jwtCommon(token).String()
}
func (s TtyStyler) JWTFull(token *jwt.Token) string {
	b := s.jwtCommon(token)
	claims := *token.Claims.(*jwt.MapClaims)

	b.NewLine()
	b.Indent()
	b.Tabs()

	// The set that we've already printed. Not quite the Registered ones, because we also print ID, which isn't in that list
	specialClaims := map[string]bool{
		"exp": true,
		"iat": true,
		"nbf": true,
		"iss": true,
		"sub": true,
		"aud": true,
		"id":  true,
	}
	for k, v := range claims {
		if !specialClaims[k] {
			b.Printf("%s: %v; ", k, v)
		}
	}

	b.Dedent()

	return b.String()
}
