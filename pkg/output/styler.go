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
)

const TimeFmt = "2006 Jan _2 15:04:05"

type TtyStyler struct {
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

func NewTtyStyler(au aurora.Aurora) TtyStyler {
	return TtyStyler{
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

func (s TtyStyler) Info(str string) aurora.Value {
	return s.au.Colorize(str, s.InfoStyle)
}
func (s TtyStyler) Fail(str string) aurora.Value {
	return s.au.Colorize(str, s.FailStyle)
}
func (s TtyStyler) Ok(str string) aurora.Value {
	return s.au.Colorize(str, s.OkStyle)
}
func (s TtyStyler) Warn(str string) aurora.Value {
	return s.au.Colorize(str, s.WarnStyle)
}
func (s TtyStyler) Addr(str string) aurora.Value {
	return s.au.Colorize(str, s.AddrStyle)
}
func (s TtyStyler) Verb(str string) aurora.Value {
	return s.au.Colorize(str, s.VerbStyle)
}
func (s TtyStyler) Noun(str string) aurora.Value {
	return s.au.Colorize(str, s.NounStyle)
}
func (s TtyStyler) Bright(v interface{}) aurora.Value {
	return s.au.Colorize(v, s.BrightStyle)
}

func (s TtyStyler) UrlPath(u *url.URL) string {
	var b strings.Builder

	// TODO: should probably use the unescaped versions of these, ie u.Path, url.UnescapeQuery(u.RawQuery), u.Fragment
	if len(u.EscapedPath()) > 0 {
		b.WriteString(s.Addr(u.EscapedPath()).String())
	} else {
		b.WriteString(s.Addr("/").String())
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
func (s TtyStyler) PathElements(path, query, fragment string) string {
	var b strings.Builder

	if len(path) > 0 {
		b.WriteString(s.Addr(path).String())
	} else {
		b.WriteString(s.Addr("/").String())
	}

	if len(query) > 0 {
		b.WriteString("?")
		b.WriteString(s.Verb(query).String())
	}

	if len(fragment) > 0 {
		b.WriteString("#")
		b.WriteString(s.Addr(fragment).String())
	}

	return b.String()
}

func (s TtyStyler) Time(t time.Time, start bool) aurora.Value {
	if start {
		if t.After(time.Now()) {
			return s.au.Colorize(t.Format(TimeFmt), s.FailStyle)
		} else {
			return s.au.Colorize(t.Format(TimeFmt), s.OkStyle)
		}
	} else {
		if t.Before(time.Now()) {
			return s.au.Colorize(t.Format(TimeFmt), s.FailStyle)
		} else if t.Before(time.Now().Add(240 * time.Hour)) {
			return s.au.Colorize(t.Format(TimeFmt), s.WarnStyle)
		} else {
			return s.au.Colorize(t.Format(TimeFmt), s.OkStyle)
		}
	}
}

func (s TtyStyler) YesNo(test bool) aurora.Value {
	if test {
		return s.au.Colorize("yes", s.OkStyle)
	}
	return s.au.Colorize("no", s.FailStyle)
}
func (s TtyStyler) YesInfo(test bool) aurora.Value {
	if test {
		return s.au.Colorize("yes", s.OkStyle)
	}
	return s.au.Colorize("no", s.InfoStyle)
}
func (s TtyStyler) YesError(err error) aurora.Value {
	if err == nil {
		return s.au.Colorize("yes", s.OkStyle)
	}
	return s.au.Colorize("no: "+err.Error(), s.FailStyle)
}
func (s TtyStyler) YesErrorWarning(err error, warning bool) aurora.Value {
	if err == nil {
		return s.au.Colorize("yes", s.OkStyle)
	}
	if warning {
		return s.au.Colorize("no: "+err.Error(), s.WarnStyle)
	}
	return s.au.Colorize("no: "+err.Error(), s.FailStyle)
}

func (s TtyStyler) OptionalString(msg string, style aurora.Color) aurora.Value {
	if msg == "" {
		return s.au.Colorize("<none>", s.InfoStyle)
	}
	return s.au.Colorize(msg, style)
}

func (s TtyStyler) List(ins []string, style aurora.Color) string {
	if len(ins) == 0 {
		return s.au.Colorize("<none>", s.InfoStyle).String()
	}

	printLen := 0
	op := ""
	for i, in := range ins {
		newPrintLen := printLen + len(in) // without the escape sequences
		if i != len(ins)-1 {
			newPrintLen += len(", ")
		}

		// TODO better algo (it has a problem, think ;)
		if newPrintLen > 80 {
			op += s.au.Colorize(in[:usvc.MinInt(80-printLen, len(in)-1)], style).String()
			op += "..."
			break
		}

		op += s.au.Colorize(in, style).String()
		if i != len(ins)-1 {
			op += ", "
		}

		printLen = newPrintLen
	}

	return op
}

func (s TtyStyler) PublicKeySummary(key crypto.PublicKey) aurora.Value {
	return s.au.Colorize(PublicKeyInfo(key), s.NounStyle)
}

func (s TtyStyler) CertSummary(cert *x509.Certificate) string {
	caFlag := s.au.Colorize("non-ca", s.InfoStyle)
	if cert.IsCA {
		caFlag = s.au.Colorize("ca", s.OkStyle)
	}

	return fmt.Sprintf(
		"[%s -> %s] %s %s sig %s [%s]",
		s.Time(cert.NotBefore, true),
		s.Time(cert.NotAfter, false),
		s.au.Colorize(cert.Subject.String(), s.AddrStyle),
		s.PublicKeySummary(cert.PublicKey),
		s.au.Colorize(cert.SignatureAlgorithm, s.NounStyle),
		// No need to print Issuer, cause that's the Subject of the next cert in the chain
		caFlag,
	)
}

func (s TtyStyler) Issuer(cert *x509.Certificate) aurora.Value {
	if cert.Issuer.String() == cert.Subject.String() {
		return s.au.Colorize("<self-signed>", s.InfoStyle)
	}
	return s.au.Colorize(cert.Issuer.String(), s.AddrStyle)
}

func (s TtyStyler) certSansRenderer(cert *x509.Certificate) {
	fmt.Printf("\t\tDNS SANs %s\n", s.List(cert.DNSNames, s.AddrStyle))
	fmt.Printf("\t\tIP SANs %s\n", s.List(Slice2Strings(cert.IPAddresses), s.AddrStyle))
}

// TODO should return string really
// TODO: condense this and all the below into one function, with options to
// - print head cert details, or not, and do so as client/server cert - make the details printer funcs public and then the caller can call this with output.FooHeadRender as an arg
// - verify signature (implied by non-nil caCert
// - Print chain
// - Print SAN info (the only difference between ServingCertChain and ClientCertChain ?)
// - Verify an addr (parse as either ip or name) against the SANs & CN
// TODO: builder pattern (and verifiedCertChain)
func (s TtyStyler) certChain(chain, verifiedCerts []*x509.Certificate, headCb func(cert *x509.Certificate)) {

	head := chain[0]
	fmt.Printf("\t0: %s\n", s.CertSummary(head))
	if headCb != nil {
		headCb(head)
	}

	certs := verifiedCerts
	if certs == nil {
		certs = chain
	}

	for i := 1; i < len(certs); i++ {
		fmt.Printf("\t%d: ", i)

		if verifiedCerts != nil {
			if i < len(chain) && certs[i].Equal(chain[i]) {
				fmt.Printf("PRESENTED")
			} else {
				fmt.Printf("INSTALLED")
			}
		}

		fmt.Printf(" %s\n", s.CertSummary(certs[i]))
	}

	fmt.Printf("\t%d: %s\n", len(certs), s.Issuer(certs[len(certs)-1]))
}

func (s TtyStyler) ServingCertChain(chain []*x509.Certificate) {
	s.certChain(chain, nil, s.certSansRenderer)
}
func (s TtyStyler) ClientCertChain(chain []*x509.Certificate) {
	s.certChain(chain, nil, nil)
}

func (s TtyStyler) VerifiedCertChain(chain []*x509.Certificate, caCert *x509.Certificate, validateAddr string, validateUsage []x509.ExtKeyUsage, headCb func(cert *x509.Certificate), verbose bool) {

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

	validChains, err := chain[0].Verify(opts)

	if err != nil {
		// Cert isn't valid: just print it and any chain it came with
		s.certChain(chain, nil, headCb) // TODO: print only the head cert in non-verbose mode (same in the other branch)
		fmt.Println()
	} else {
		// Cert is valid: print any and all paths to validation
		fmt.Println("\tValidation chain(s):")
		for _, chain := range validChains {
			s.certChain(chain, chain, headCb)
			fmt.Println()
		}
	}

	if verbose {
		if caCert != nil {
			fmt.Println("\tValidating against", s.CertSummary(caCert))
		} else {
			fmt.Println("\tValidating against system certs")
		}
		fmt.Println()
	}
	fmt.Println("\tCert valid?", s.YesError(err))

	if validateAddr != "" {
		if ip := net.ParseIP(validateAddr); ip != nil {
			validateAddr = "[" + ip.String() + "]"
		}
		fmt.Printf(
			"\tName valid, ie SNI %s in SANs? %s; in CN? %s\n",
			s.au.Colorize(validateAddr, s.AddrStyle),
			s.YesError(head.VerifyHostname(validateAddr)),
			s.YesInfo(strings.EqualFold(head.Subject.CommonName, validateAddr)),
		)
	}

	fmt.Println()
}

func (s TtyStyler) VerifiedServingCertChain(chain []*x509.Certificate, caCert *x509.Certificate, validateAddr string, verbose bool) {
	s.VerifiedCertChain(chain, caCert, validateAddr, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, s.certSansRenderer, verbose)
}
func (s TtyStyler) VerifiedClientCertChain(chain []*x509.Certificate, caCert *x509.Certificate, verbose bool) {
	s.VerifiedCertChain(chain, caCert, "", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, verbose)
}

func (s TtyStyler) JWTSummary(token *jwt.Token) {
	fmt.Print(s.Noun("JWT").String())
	claims := token.Claims.(*jwt.RegisteredClaims)

	/* Times */

	fmt.Printf(" [")

	start := claims.IssuedAt
	if claims.NotBefore != nil {
		start = claims.NotBefore
	}
	if start != nil {
		fmt.Print(s.Time(start.Time, true))
	} else {
		fmt.Print(s.Fail("?").String())
	}

	fmt.Print(" -> ")

	if claims.ExpiresAt != nil {
		fmt.Print(s.Time(claims.ExpiresAt.Time, false))
	} else {
		fmt.Print(s.Fail("?").String())
	}

	fmt.Print("]")

	/* Other claims */

	if claims.ID != "" {
		fmt.Printf(" id %s", s.Bright(claims.ID))
	}

	if claims.Subject != "" {
		fmt.Printf(" subj %s", s.Addr(claims.Subject))
	}

	if claims.Issuer != "" {
		fmt.Printf(" iss %s", s.Addr(claims.Issuer))
	}

	if len(claims.Audience) != 0 {
		fmt.Printf(" aud %s", s.List(claims.Audience, s.AddrStyle))
	}
}
