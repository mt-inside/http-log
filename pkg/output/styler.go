package output

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/logrusorgru/aurora/v3"
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
	return s.au.Colorize(err, s.FailStyle)
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
			op += s.au.Colorize(in[:min(80-printLen, len(in)-1)], style).String()
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

func (s TtyStyler) Issuer(cert *x509.Certificate) aurora.Value {
	if cert.Issuer.String() == cert.Subject.String() {
		return s.au.Colorize("<self-signed>", s.InfoStyle)
	}
	return s.au.Colorize(cert.Issuer.String(), s.AddrStyle)
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

// TODO should return string really
func (s TtyStyler) certChain(peerCerts, verifiedCerts []*x509.Certificate, headCb func(head *x509.Certificate)) {

	head := peerCerts[0]
	fmt.Printf("\t0 (presented): %s\n", s.CertSummary(head))
	if headCb != nil {
		headCb(head)
	}

	certs := verifiedCerts
	if certs == nil {
		certs = peerCerts
	}

	for i := 1; i < len(certs); i++ {
		fmt.Printf("\t%d", i)

		if i < len(peerCerts) && certs[i].Equal(peerCerts[i]) {
			fmt.Printf(" (presented):")
		} else {
			fmt.Printf(" (installed):")
		}

		fmt.Printf(" %s\n", s.CertSummary(certs[i]))
	}

	fmt.Printf("\t%d: %s\n", len(certs), s.Issuer(certs[len(certs)-1]))
}

// TODO just take an addr string, try parse as IP, if so use "[ip.String()]"
// ServingCertChain prints the entire cert chain, rendering information relevant to server certs.
// This function does not attempt to veryify the certs, and should only be used for eg printing certs that we present, not that we receive
func (s TtyStyler) ServingCertChain(name *string, ip *net.IP, peerCerts, verifiedCerts []*x509.Certificate) {
	var addr string
	if name != nil {
		addr = *name
	} else if ip != nil {
		addr = "[" + ip.String() + "]"
	} else {
		panic(errors.New("need either a name or IP to check serving cert against"))
	}

	s.certChain(
		peerCerts, verifiedCerts,
		func(head *x509.Certificate) {
			fmt.Printf("\t\tDNS SANs %s\n", s.List(head.DNSNames, s.AddrStyle))
			fmt.Printf("\t\tIP SANs %s\n", s.List(Slice2Strings(head.IPAddresses), s.AddrStyle))
			fmt.Printf(
				"\t\tSNI %s in SANs? %s (CN? %s)\n",
				s.au.Colorize(*name, s.AddrStyle),
				s.YesError(head.VerifyHostname(addr)),
				s.YesInfo(strings.EqualFold(head.Subject.CommonName, *name)),
			)
		},
	)
}

func (s TtyStyler) ServingCertChainVerified(name string, peerCerts []*x509.Certificate, caCert *x509.Certificate) {
	opts := x509.VerifyOptions{
		DNSName:       name,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if caCert != nil {
		// If no custom CA is given, leave opts.Roots nil, which uses system roots to verify
		opts.Roots = x509.NewCertPool()
		opts.Roots.AddCert(caCert)
	}
	for _, cert := range peerCerts[1:] {
		opts.Intermediates.AddCert(cert)
	}

	chains, err := peerCerts[0].Verify(opts)
	if err != nil {
		s.ServingCertChain(&name, nil, peerCerts, nil)
		fmt.Println()
	} else {
		for _, chain := range chains {
			s.ServingCertChain(&name, nil, peerCerts, chain)
			fmt.Println()
		}
	}

	fmt.Println("\tValidating against", s.CertSummary(caCert)) // TODO: verbose mode only
	fmt.Println("\tCert valid?", s.YesError(err))
}

// TODO should return string really
// ClientCertChain prints the entire cert chain, rendering information relevant to client certs.
// This function does not attempt to veryify the certs, and should only be used for eg printing certs that we present, not that we receive
func (s TtyStyler) ClientCertChain(peerCerts, verifiedCerts []*x509.Certificate) {
	s.certChain(peerCerts, verifiedCerts, nil)
}

func (s TtyStyler) ClientCertChainVerified(peerCerts []*x509.Certificate, caCert *x509.Certificate) {
	opts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if caCert != nil {
		// If no custom CA is given, leave opts.Roots nil, which uses system roots to verify
		// Most likely these will fail to verify a client cert, but 🤷‍♀️ the host setup
		opts.Roots = x509.NewCertPool()
		opts.Roots.AddCert(caCert)
	}
	for _, cert := range peerCerts[1:] {
		opts.Intermediates.AddCert(cert)
	}

	chains, err := peerCerts[0].Verify(opts)
	if err != nil {
		s.ClientCertChain(peerCerts, nil)
		fmt.Println()
	} else {
		for _, chain := range chains {
			s.ClientCertChain(peerCerts, chain)
			fmt.Println()
		}
	}

	fmt.Println("\tValidating against", s.CertSummary(caCert)) // TODO: verbose mode only
	fmt.Println("\tCert valid?", s.YesError(err))
}
