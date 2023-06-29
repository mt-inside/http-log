package output

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/logrusorgru/aurora/v3"

	"github.com/mt-inside/go-usvc"

	"github.com/mt-inside/http-log/pkg/utils"
)

type TtyStyler struct {
	au aurora.Aurora
}

const (
	timeFmt = "2006 Jan _2 15:04:05"

	InfoStyle aurora.Color = aurora.BlackFg | aurora.BrightFg
	FailStyle aurora.Color = aurora.RedFg
	OkStyle   aurora.Color = aurora.GreenFg
	WarnStyle aurora.Color = aurora.YellowFg

	AddrStyle   aurora.Color = aurora.BlueFg
	VerbStyle   aurora.Color = aurora.MagentaFg
	NounStyle   aurora.Color = aurora.CyanFg
	BrightStyle aurora.Color = aurora.WhiteFg | aurora.BrightFg
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

func (s TtyStyler) List(ins []string, style aurora.Color) string {
	var b strings.Builder

	if len(ins) == 0 {
		return s.au.Colorize("<none>", InfoStyle).String()
	}

	printLen := 0
	for i, in := range ins {
		newPrintLen := printLen + len(in) // without the escape sequences
		if i != len(ins)-1 {
			newPrintLen += len(", ")
		}

		// TODO better algo (it has a problem, think ;)
		if newPrintLen > 80 {
			b.WriteString(s.au.Colorize(in[:usvc.MinInt(80-printLen, len(in)-1)], style).String())
			b.WriteString("...")
			break
		}

		b.WriteString(s.au.Colorize(in, style).String())
		if i != len(ins)-1 {
			b.WriteString(", ")
		}

		printLen = newPrintLen
	}

	return b.String()
}

func (s TtyStyler) PublicKeySummary(key crypto.PublicKey) string {
	return s.Noun(PublicKeyInfo(key))
}

func (s TtyStyler) CertSummary(cert *x509.Certificate) string {
	caFlag := s.Info("non-ca")
	if cert.IsCA {
		caFlag = s.Ok("ca")
	}

	return fmt.Sprintf(
		"[%s -> %s] %s %s sig %s [%s]",
		s.TimeOkExpired(cert.NotBefore, true),
		s.TimeOkExpired(cert.NotAfter, false),
		s.Addr(cert.Subject.String()),
		s.PublicKeySummary(cert.PublicKey),
		s.Noun(cert.SignatureAlgorithm.String()),
		// No need to print Issuer, cause that's the Subject of the next cert in the chain
		caFlag,
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
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 && len(cert.URIs) == 0 && len(cert.EmailAddresses) == 0 {
		b.Printf(s.Info(" <none>"))
		return b.String()
	}

	b.NewLine()
	b.Indent()
	if len(cert.DNSNames) > 0 {
		b.Linef("DNS: %s", s.List(cert.DNSNames, AddrStyle))
	}
	if len(cert.IPAddresses) > 0 {
		b.Linef("IPs: %s", s.List(Slice2Strings(cert.IPAddresses), AddrStyle))
	}
	if len(cert.URIs) > 0 {
		b.Linef("URIs: %s", s.List(utils.Map(cert.URIs, s.Url), AddrStyle))
	}
	if len(cert.EmailAddresses) > 0 {
		b.Linef("Emails: %s", s.List(cert.EmailAddresses, AddrStyle))
	}
	b.Dedent()

	return b.String()
}

// TODO DONE?: condense this and all the below into one function, with options to
// - print head cert details, or not, and do so as client/server cert - make the details printer funcs public and then the caller can call this with output.FooHeadRender as an arg
// - verify signature (implied by non-nil caCert
// - Print chain
// - Print SAN info (the only difference between ServingCertChain and ClientCertChain ?)
// - Verify an addr (parse as either ip or name) against the SANs & CN
// TODO: builder pattern (and verifiedCertChain)
func (s TtyStyler) certChain(chain, verifiedCerts []*x509.Certificate, headCb func(cert *x509.Certificate) string) string {
	var b IndentingBuilder

	head := chain[0]
	b.Linef("0: %s", s.CertSummary(head))
	if headCb != nil {
		b.Indent()
		b.Block(headCb(head))
		b.Dedent()
	}

	certs := verifiedCerts
	if certs == nil {
		certs = chain
	}

	for i := 1; i < len(certs); i++ {
		b.Tabs()
		b.Printf("%d: ", i)

		if verifiedCerts != nil {
			if i < len(chain) && certs[i].Equal(chain[i]) {
				b.Print("PRESENTED")
			} else {
				b.Print("INSTALLED")
			}
		}

		b.Printf(" %s", s.CertSummary(certs[i]))
		b.NewLine()
	}

	b.Linef("%d: %s", len(certs), s.Issuer(certs[len(certs)-1]))

	return b.String()
}

func (s TtyStyler) ServingCertChain(chain []*x509.Certificate) string {
	return s.certChain(chain, nil, s.certSansRenderer)
}
func (s TtyStyler) ClientCertChain(chain []*x509.Certificate) string {
	return s.certChain(chain, nil, nil)
}

func (s TtyStyler) VerifiedCertChain(
	chain []*x509.Certificate,
	caCert *x509.Certificate,
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
	if caCert != nil {
		// If no custom CA is given, leave opts.Roots nil, which uses system roots to verify. Ie can't give an _empty_ opts.Roots
		opts.Roots = x509.NewCertPool()
		opts.Roots.AddCert(caCert)
	}
	for _, cert := range chain[1:] {
		opts.Intermediates.AddCert(cert)
	}

	if verbose {
		if caCert != nil {
			b.Linef("Validating against: %s", s.CertSummary(caCert))
		} else {
			b.Line("Validating against system certs")
		}
		b.NewLine()
	}

	validChains, err := chain[0].Verify(opts)

	if err != nil {
		// Cert isn't valid: just print it and any chain it came with
		b.Block(s.certChain(chain, nil, headCb)) // TODO: print only the head cert in non-verbose mode (same in the other branch)
		b.NewLine()
	} else {
		// Cert is valid: print any and all paths to validation
		// TODO: something (styler) needs an "indent writer" that targets a Builder and has the indent/dedent functions. Generalises over what bios does (bios should defer to that and actually output)
		// - bios doesn't actually need it then; the binaries can just use it from styler and fmt.Print the result, bios can do the same
		// - NewLine method too
		b.Line("Validation chain(s):")
		b.Indent()
		for _, chain := range validChains {
			b.Block(s.certChain(chain, chain, headCb))
			b.NewLine()
		}
		b.Dedent()
	}

	b.Linef("Cert valid? %s", s.YesError(err))

	if validateAddr != "" {
		if ip := net.ParseIP(validateAddr); ip != nil {
			validateAddr = "[" + ip.String() + "]"
		}
		b.Linef("Requested SNI (%s) in SANs? %s; in CN? %s",
			s.au.Colorize(validateAddr, AddrStyle),
			s.YesError(head.VerifyHostname(validateAddr)),
			s.YesInfo(strings.EqualFold(head.Subject.CommonName, validateAddr)),
		)
	}

	b.NewLine()

	return b.String()
}

func (s TtyStyler) VerifiedServingCertChain(chain []*x509.Certificate, caCert *x509.Certificate, validateAddr string, verbose bool) string {
	return s.VerifiedCertChain(chain, caCert, validateAddr, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, s.certSansRenderer, verbose)
}
func (s TtyStyler) VerifiedClientCertChain(chain []*x509.Certificate, caCert *x509.Certificate, verbose bool) string {
	return s.VerifiedCertChain(chain, caCert, "", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, verbose)
}

func (s TtyStyler) JWTSummary(token *jwt.Token) string {
	var b strings.Builder

	b.WriteString(s.Noun("JWT"))
	claims := token.Claims.(*jwt.RegisteredClaims)

	/* Times */

	b.WriteString(" [")

	start := claims.IssuedAt
	if claims.NotBefore != nil {
		start = claims.NotBefore
	}
	if start != nil {
		b.WriteString(s.TimeOkExpired(start.Time, true))
	} else {
		b.WriteString(s.Fail("?"))
	}

	b.WriteString(" -> ")

	if claims.ExpiresAt != nil {
		b.WriteString(s.TimeOkExpired(claims.ExpiresAt.Time, false))
	} else {
		b.WriteString(s.Fail("?"))
	}

	b.WriteString("]")

	/* Other claims */

	if claims.ID != "" {
		fmt.Fprintf(&b, " id %s", s.Bright(claims.ID))
	}

	if claims.Subject != "" {
		fmt.Fprintf(&b, " subj %s", s.Addr(claims.Subject))
	}

	if claims.Issuer != "" {
		fmt.Fprintf(&b, " iss %s", s.Addr(claims.Issuer))
	}

	if len(claims.Audience) != 0 {
		fmt.Fprintf(&b, " aud %s", s.List(claims.Audience, AddrStyle))
	}

	return b.String()
}
