package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/jessevdk/go-flags"
	"github.com/logrusorgru/aurora/v3"
	"github.com/mattn/go-isatty"

	"github.com/mt-inside/go-usvc"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/utils"
)

/* TODO:
* combine code with lb-checker - stuff to render certs, tls.connectionstate, etc
* option to demand client certs, print them
* if present, print
*   basic auth credentials
 */

func init() {
	spew.Config.DisableMethods = true
	spew.Config.DisablePointerMethods = true
}

type renderer interface {
	Listen(addr net.Addr)
	KeySummary(key crypto.PublicKey, keyUse string)
	CertSummary(cert *x509.Certificate, certUse string)
	Connection(requestNo uint, c net.Conn)
	TLSNegSummary(cs *tls.ClientHelloInfo)
	TLSNegFull(cs *tls.ClientHelloInfo)
	TLSSummary(cs *tls.ConnectionState, clientCA *x509.Certificate)
	TLSFull(cs *tls.ConnectionState, clientCA *x509.Certificate)
	HeadSummary(proto, method, host, ua string, url *url.URL, respCode int)
	HeadFull(r *http.Request, respCode int)
	JWTSummary(tokenErr error, warning bool, start, end *time.Time, ID, subject, issuer string, audience []string)
	JWTFull(tokenErr error, warning bool, start, end *time.Time, ID, subject, issuer string, audience []string, sigAlgo, hashAlgo string)
	BodySummary(contentType string, contentLength int64, body []byte)
	BodyFull(contentType string, contentLength int64, body []byte)
}

var requestNo uint

type logMiddle struct {
	b              output.Bios
	next           http.Handler
	output         renderer
	selfSign       bool
	certPair       *tls.Certificate // TODO why u a pointer?
	clientCA       *x509.Certificate
	jwtValidateKey crypto.PublicKey
}

func (lm logMiddle) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	/* Headers */

	userAgent := codec.FirstHeaderFromRequest(r, "User-Agent")
	jwt, jwtErr, jwtFound := codec.TryExtractJWT(r, lm.jwtValidateKey)

	if opts.HeadFull {
		lm.output.HeadFull(r, opts.Status)
		if jwtFound {
			start, end, ID, subject, issuer, audience, sigAlgo, hashAlgo := codec.JWT(jwt)
			lm.output.JWTFull(jwtErr, errors.Is(jwtErr, codec.NoValidationKeyError{}), start, end, ID, subject, issuer, audience, sigAlgo, hashAlgo)
		}
	} else if opts.HeadSummary {
		// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
		lm.output.HeadSummary(r.Proto, r.Method, r.Host, userAgent, r.URL, opts.Status)
		if jwtFound {
			start, end, ID, subject, issuer, audience, _, _ := codec.JWT(jwt)
			lm.output.JWTSummary(jwtErr, errors.Is(jwtErr, codec.NoValidationKeyError{}), start, end, ID, subject, issuer, audience)
		}
	}

	// TODO: render properly
	hops := codec.ExtractProxies(r)
	for _, hop := range hops {
		fmt.Printf("%s --[http/%s tls %t]-> %s @ %s (%s)\n", hop.Client, hop.Version, hop.TLS, hop.Target, hop.Host, hop.Agent)
	}

	/* Body */

	contentType := codec.FirstHeaderFromRequest(r, "Content-Type")
	// Print only if the method would traditionally have a body, or one has been sent
	if (opts.BodyFull || opts.BodySummary) && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
		bs, err := io.ReadAll(r.Body)
		lm.b.CheckErr(err)

		if opts.BodyFull {
			lm.output.BodyFull(contentType, r.ContentLength, bs)
		} else if opts.BodySummary {
			lm.output.BodySummary(contentType, r.ContentLength, bs)
		}
	}

	/* Next */

	lm.next.ServeHTTP(w, r)
}

// TODO: move into main. Anything preventing that is wrong
var opts struct {
	// TODO: take user-specified key and cert to serve (mutex with -K)
	// TODO: take client cert CA, print whether client cert is valid (same log print-cert uses for server certs)
	// TODO: take timeout for all network ops (in here and the TLSConfig too) - https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
	/* General options */
	ListenAddr string        `short:"a" long:"addr" description:"Listen address eg 127.0.0.1:8080" default:":8080"`
	Status     int           `short:"s" long:"status" description:"HTTP status code to return" default:"200"`
	Response   string        `short:"r" long:"response" description:"HTTP response body format" choice:"none" choice:"text" choice:"json" choice:"xml" default:"text"`
	Timeout    time.Duration `long:"timeout" description:"Timeout for each individual network operation"`

	/* TLS and validation */
	Cert            string `short:"c" long:"cert" optional:"yes" description:"Path to TLS server certificate. Setting this implies serving https"`
	Key             string `short:"k" long:"key" optional:"yes" description:"Path to TLS server key. Setting this implies serving https"`
	TLSAlgo         string `short:"K" long:"self-signed-tls" choice:"off" choice:"rsa" choice:"ecdsa" choice:"ed25519" default:"off" optional:"yes" optional-value:"rsa" description:"Generate and present a self-signed TLS certificate? No flag / -k=off: plaintext. -k: TLS with RSA certs. -k=foo TLS with $foo certs"`
	ClientCA        string `short:"C" long:"ca" optional:"yes" description:"Path to TLS client CA certificate"`
	JWTValidatePath string `short:"j" long:"jwt-validate-key" description:"Path to a PEM-encoded [rsa,ecdsa,ed25519] public key used to validate JWTs"`

	/* Logging settings */
	Output             string `short:"o" long:"output" description:"Log output format" choice:"auto" choice:"pretty" choice:"text" choice:"json" default:"auto"`
	NegotiationSummary bool   `short:"n" long:"negotiation" description:"Print transport (eg TLS) setup negotiation summary, notable the SNI ServerName being requested"`
	NegotiationFull    bool   `short:"N" long:"negotiation-full" description:"Print transport (eg TLS) setup negotiation values, ie what both sides offer to support"`
	TLSSummary         bool   `short:"t" long:"tls" description:"Print important agreed TLS parameters"`
	TLSFull            bool   `short:"T" long:"tls-full" description:"Print all agreed TLS parameters"`
	HeadSummary        bool   `short:"m" long:"head" description:"Print important HTTP request metadata"`
	HeadFull           bool   `short:"M" long:"head-full" description:"Print all HTTP request metadata"`
	BodySummary        bool   `short:"b" long:"body" description:"Print truncated HTTP request body"`
	BodyFull           bool   `short:"B" long:"body-full" description:"Print full HTTP request body"`
}

// TODO: cobra + viper(? - go-flags is really nice)
func main() {

	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}

	if opts.Output == "auto" {
		if isatty.IsTerminal(os.Stdout.Fd()) {
			opts.Output = "pretty"
		} else {
			opts.Output = "json"
		}
	}

	//var s output.TtyStyler // TODO iface when log styler
	var b output.Bios
	var op renderer
	switch opts.Output {
	case "text":
		s := output.NewTtyStyler(aurora.NewAurora(false)) // no color
		b = output.NewTtyBios(s)
		op = output.NewTtyRenderer(s)
	case "pretty":
		s := output.NewTtyStyler(aurora.NewAurora(true)) // color
		b = output.NewTtyBios(s)
		op = output.NewTtyRenderer(s)
	case "json":
		// TODO: verbosity option
		l := usvc.GetLogger(false, 0)
		b = output.NewLogBios(l)
		op = output.NewLogRenderer(l)
	default:
		panic(errors.New("bottom"))
	}

	if !opts.NegotiationSummary && !opts.NegotiationFull &&
		!opts.TLSSummary && !opts.TLSFull &&
		!opts.HeadSummary && !opts.HeadFull &&
		!opts.BodySummary && !opts.BodyFull {
		opts.HeadSummary = true
	}

	b.Trace("http-log", "version", "0.5")

	handler := func(w http.ResponseWriter, r *http.Request) {
		// TODO (where? mux?) print the proxy route to get here - all x-forwarded-for, via, etc headers. test in istio. does go transparently handle proxy protocol?
		w.Header().Set("server", "http-log 0.5")
		bytes, mime := codec.BytesAndMime(opts.Status, codec.GetBody(), opts.Response)
		w.Header().Set("Content-Type", mime)
		w.WriteHeader(opts.Status)
		_, err = w.Write(bytes)
		b.CheckErr(err)
	}

	mux := &http.ServeMux{}
	mux.HandleFunc("/", handler)
	loggingMux := &logMiddle{
		b:      b,
		next:   mux,
		output: op,
	}

	https := false
	if opts.Cert != "" || opts.Key != "" || opts.TLSAlgo != "off" {
		https = true

		if opts.Cert != "" || opts.Key != "" {
			if opts.TLSAlgo != "off" {
				b.PrintErr("Can't supply TLS key+cert and also ask for self-signed")
			}

			if opts.Cert == "" || opts.Key == "" {
				b.PrintErr("Must supply both TLS server key and certificate")
			}

			servingPair, err := tls.LoadX509KeyPair(opts.Cert, opts.Key)
			b.CheckErr(err)
			loggingMux.certPair = &servingPair
		}

		if opts.TLSAlgo != "off" {
			loggingMux.selfSign = true
			loggingMux.certPair, err = utils.GenSelfSignedCa(b.GetLogger(), opts.TLSAlgo)
			b.CheckErr(err)
		}

		if loggingMux.selfSign {
			op.CertSummary(codec.HeadFromCertificate(loggingMux.certPair), "serving CA")
		} else {
			// TODO print whole chain here (styler has a method for this, expose on op)
			op.CertSummary(codec.HeadFromCertificate(loggingMux.certPair), "serving")
		}
	}

	if opts.ClientCA != "" {
		if !https {
			b.PrintErr("Can't verify TLS client certs without serving TLS")
		}

		bytes, err := ioutil.ReadFile(opts.ClientCA)
		b.CheckErr(err)
		loggingMux.clientCA, err = codec.ParseCertificate(bytes)
		b.CheckErr(err)

		op.CertSummary(loggingMux.clientCA, "client CA")
	}

	if opts.JWTValidatePath != "" {
		bytes, err := ioutil.ReadFile(opts.JWTValidatePath)
		b.CheckErr(err)
		loggingMux.jwtValidateKey, err = codec.ParsePublicKey(bytes)
		b.CheckErr(err)

		op.KeySummary(loggingMux.jwtValidateKey, "JWT validation")
	}

	srv := &http.Server{
		Addr:              opts.ListenAddr,
		ReadHeaderTimeout: 120 * time.Second, // Time for reading request headers
		ReadTimeout:       120 * time.Second, // Time for reading request headers + body
		WriteTimeout:      120 * time.Second, // Time for writing response (headers + body?)
		IdleTimeout:       120 * time.Second, // Time between requests before the connection is dropped, when keep-alives are used.
		Handler:           loggingMux,
		BaseContext: func(l net.Listener) context.Context {
			if https {
				// l is a *tls.listener but it's unexported so can't cast to it
				op.Listen(l.Addr())
			} else {
				lis := l.(*net.TCPListener)
				op.Listen(lis.Addr())
			}
			return context.Background()
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// Note: ctx has a bunch of info under context-key "http-server"

			requestNo++ // Think everything is single-threaded...
			// TODO: tcp/connection op should be an option. For print-cert too.
			op.Connection(requestNo, c)

			return ctx
		},
		ConnState: func(c net.Conn, cs http.ConnState) {
			b.Trace("HTTP server connection state change", "State", cs)
		},
	}

	if https {
		srv.TLSConfig = &tls.Config{
			ClientAuth: tls.RequestClientCert, // request but don't require. TODO when we verify them, this should be VerifyClientCertIfGiven
			/* Hooks in order they're called */
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				b.Trace("TLS ClientHello received")

				if opts.NegotiationFull {
					op.TLSNegFull(hi)
				} else if opts.NegotiationSummary {
					op.TLSNegSummary(hi)
				}

				return nil, nil // option to bail handshake or change TLSConfig
			},
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if loggingMux.selfSign {
					cert, err := utils.GenServingCert(b.GetLogger(), hi, loggingMux.certPair, opts.TLSAlgo)
					//op.CertSummary(codec.HeadFromCertificate(cert), "generated serving")
					return cert, err
				}
				return loggingMux.certPair, nil
			},
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				b.Trace("TLS built-in cert verification finished")
				return nil // can do extra cert verification and reject
			},
			VerifyConnection: func(cs tls.ConnectionState) error {
				b.Trace("TLS: all cert verification finished")

				if opts.TLSFull {
					op.TLSFull(&cs, loggingMux.clientCA)
				} else if opts.TLSSummary {
					// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
					op.TLSSummary(&cs, loggingMux.clientCA)
				}

				return nil // can inspect all connection and TLS info and reject
			},
		}
		b.CheckErr(srv.ListenAndServeTLS("", ""))
		b.Trace("Shutting down")
	} else {
		b.CheckErr(srv.ListenAndServe())
		b.Trace("Shutting down")
	}
}
