package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
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
*   credentials
*   - decode JWTs, allow supply of jwks to verify them
 */

func init() {
	spew.Config.DisableMethods = true
	spew.Config.DisablePointerMethods = true
}

type renderer interface {
	Connection(requestNo uint, c net.Conn)
	TLSNegSummary(cs *tls.ClientHelloInfo)
	TLSNegFull(cs *tls.ClientHelloInfo)
	TLSSummary(cs *tls.ConnectionState)
	TLSFull(cs *tls.ConnectionState)
	HeadSummary(proto, method, host, ua string, url *url.URL, respCode int)
	HeadFull(r *http.Request, respCode int)
	JWTSummary(tokenErr error, start, end *time.Time, ID, subject, issuer string, audience []string)
	JWTFull(tokenErr error, start, end *time.Time, ID, subject, issuer string, audience []string, sigAlgo, hashAlgo string)
	BodySummary(contentType string, contentLength int64, body []byte)
	BodyFull(contentType string, contentLength int64, body []byte)
}

var requestNo uint

type logMiddle struct {
	b      output.Bios
	next   http.Handler
	output renderer
	caPair *tls.Certificate
}

func (lm logMiddle) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	/* Headers */

	userAgent := codec.HeaderFromRequest(r, "User-Agent")
	jwt, jwtErr, jwtFound := codec.TryExtractJWT(lm.b, r, opts.JWTValidatePath)

	if opts.HeadFull {
		lm.output.HeadFull(r, opts.Status)
		if jwtFound {
			start, end, ID, subject, issuer, audience, sigAlgo, hashAlgo := codec.JWT(jwt)
			lm.output.JWTFull(jwtErr, start, end, ID, subject, issuer, audience, sigAlgo, hashAlgo)
		}
	} else if opts.HeadSummary {
		// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
		lm.output.HeadSummary(r.Proto, r.Method, r.Host, userAgent, r.URL, opts.Status)
		if jwtFound {
			start, end, ID, subject, issuer, audience, _, _ := codec.JWT(jwt)
			lm.output.JWTSummary(jwtErr, start, end, ID, subject, issuer, audience)
		}
	}

	/* Body */

	contentType := codec.HeaderFromRequest(r, "Content-Type")
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

var opts struct {
	// TODO: take user-specified key and cert to serve (mutex with -K)
	// TODO: take client cert CA, print whether client cert is valid (same log print-cert uses for server certs)
	// TODO: take timeout for all network ops
	ListenAddr         string `short:"a" long:"addr" description:"Listen address eg 127.0.0.1:8080" default:":8080"`
	TLSAlgo            string `short:"K" long:"self-signed-tls" choice:"off" choice:"rsa" choice:"ecdsa" choice:"ed25519" default:"off" optional:"yes" optional-value:"rsa" description:"Generate and present a self-signed TLS certificate? No flag / -k=off: plaintext. -k: TLS with RSA certs. -k=foo TLS with $foo certs"`
	NegotiationSummary bool   `short:"n" long:"negotiation" description:"Print transport (eg TLS) setup negotiation summary, notable the SNI ServerName being requested"`
	NegotiationFull    bool   `short:"N" long:"negotiation-full" description:"Print transport (eg TLS) setup negotiation values, ie what both sides offer to support"`
	TLSSummary         bool   `short:"t" long:"tls" description:"Print important agreed TLS parameters"`
	TLSFull            bool   `short:"T" long:"tls-full" description:"Print all agreed TLS parameters"`
	HeadSummary        bool   `short:"m" long:"head" description:"Print important header values"`
	HeadFull           bool   `short:"M" long:"head-full" description:"Print entire request head"`
	JWTValidatePath    string `short:"j" long:"jwt-validate-key" description:"Path to a PEM-encoded [rsa,ecdsa,ed25519] public key used to validate JWTs"`
	BodySummary        bool   `short:"b" long:"body" description:"Print truncated body"`
	BodyFull           bool   `short:"B" long:"body-full" description:"Print full body"`
	Output             string `short:"o" long:"output" description:"Log output format" choice:"auto" choice:"pretty" choice:"text" choice:"json" default:"auto"`
	Response           string `short:"r" long:"response" description:"HTTP response body format" choice:"none" choice:"text" choice:"json" choice:"xml" default:"text"`
	Status             int    `short:"s" long:"status" description:"Http status code to return" default:"200"`
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

	if opts.TLSAlgo != "off" {
		loggingMux.caPair, err = utils.GenSelfSignedCa(b, opts.TLSAlgo)
		if err != nil {
			panic(err)
		}
	}

	srv := &http.Server{
		Addr:         opts.ListenAddr,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      loggingMux,
		BaseContext: func(l net.Listener) context.Context {
			switch l.(type) {
			case *net.TCPListener:
				b.Trace("HTTP server listening", "Addr", l.Addr(), "transport", "plaintext")
			default: // *tls.listener assumed
				b.Trace("HTTP server listening", "Addr", l.Addr(), "transport", "tls", "algo", opts.TLSAlgo)
			}
			return context.Background()
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// Note: ctx has a bunch of info under context-key "http-server"

			requestNo++ // Think everything is single-threaded...
			op.Connection(requestNo, c)

			return ctx
		},
		ConnState: func(c net.Conn, cs http.ConnState) {
			b.Trace("HTTP server connection state change", "State", cs)
		},
	}

	if opts.TLSAlgo != "off" {
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
				return utils.GenServingCert(b, hi, loggingMux.caPair, opts.TLSAlgo)
			},
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				b.Trace("TLS built-in cert verification finished")
				return nil // can do extra cert verification and reject
			},
			VerifyConnection: func(cs tls.ConnectionState) error {
				b.Trace("TLS: all cert verification finished")

				if opts.TLSFull {
					op.TLSFull(&cs)
				} else if opts.TLSSummary {
					// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
					op.TLSSummary(&cs)
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
