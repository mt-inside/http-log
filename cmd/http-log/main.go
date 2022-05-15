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
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/jessevdk/go-flags"
	"github.com/logrusorgru/aurora/v3"
	"github.com/mattn/go-isatty"

	"github.com/mt-inside/go-usvc"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/state"
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
	// TODO: this block
	// TODO: then start moving things around, eg Hops with connection, HSTS with TLS (is a print-cert thing but that needs the same treatment)
	Listen(d *state.DaemonData)
	KeySummary(key crypto.PublicKey, keyUse string)
	CertSummary(cert *x509.Certificate, certUse string)
	BodySummary(contentType string, contentLength int64, body []byte)
	BodyFull(contentType string, contentLength int64, body []byte)

	TcpConnection(d *state.RequestData)
	TLSNegSummary(d *state.RequestData)
	TLSNegFull(d *state.RequestData)
	TLSAgreedSummary(s *state.DaemonData, r *state.RequestData)
	TLSAgreedFull(s *state.DaemonData, r *state.RequestData)
	HeadSummary(d *state.RequestData)
	HeadFull(d *state.RequestData)
}

var requestNo uint

type logMiddle struct {
	b       output.Bios
	next    http.Handler
	output  renderer
	reqData *state.RequestData
	srvData *state.DaemonData
}

func (lm logMiddle) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	/* Headers */

	codec.ParseHttpRequest(r, lm.srvData, lm.reqData)

	// TODO: render properly, move to OP
	hops := codec.ExtractProxies(lm.reqData, lm.srvData)
	for _, hop := range hops {
		proto := "http"
		if hop.TLS {
			proto = "https"
		}
		fmt.Printf("%s --[%s/%s]-> %s@%s (%s)\n", net.JoinHostPort(hop.ClientHost, hop.ClientPort), proto, hop.Version, hop.VHost, net.JoinHostPort(hop.ServerHost, hop.ServerPort), hop.ServerAgent)
	}

	/* Body */

	contentType := codec.FirstHeaderFromRequest(r.Header, "Content-Type")
	// Print only if the method would traditionally have a body, or one has been sent
	if (opts.BodyFull || opts.BodySummary) && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
		bs, err := io.ReadAll(r.Body)
		lm.b.CheckErr(err)

		if opts.BodyFull {
			lm.output.BodyFull(contentType, r.ContentLength, bs)
		} else if opts.BodySummary {
			lm.output.BodySummary(contentType, r.ContentLength, bs)
		}
		codec.ParseHttpRequest(r, lm.srvData, lm.reqData)
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

	srvData := state.NewDaemonData()
	reqData := state.NewRequestData()

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
		//op = output.NewLogRenderer(l) FIXME
		//op = output.NewTtyRenderer(s)
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
		reqData.HttpResponseCode = opts.Status
		_, err = w.Write(bytes)
		b.CheckErr(err)

		// TODO: tcp/connection op should be an option. For print-cert too.
		op.TcpConnection(reqData)
		if opts.NegotiationFull {
			op.TLSNegFull(reqData)
		} else if opts.NegotiationSummary {
			op.TLSNegSummary(reqData)
		}
		if opts.TLSFull {
			op.TLSAgreedFull(srvData, reqData)
		} else if opts.TLSSummary {
			// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
			op.TLSAgreedSummary(srvData, reqData)
		}
		if opts.HeadFull {
			op.HeadFull(reqData)
		} else if opts.HeadSummary {
			// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
			op.HeadSummary(reqData)
		}
	}

	mux := &http.ServeMux{}
	mux.HandleFunc("/", handler)
	loggingMux := &logMiddle{
		b:       b,
		next:    mux,
		output:  op,
		reqData: reqData,
		srvData: srvData,
	}

	srvData.TlsOn = false
	if opts.Cert != "" || opts.Key != "" || opts.TLSAlgo != "off" {
		srvData.TlsOn = true

		if opts.Cert != "" || opts.Key != "" {
			if opts.TLSAlgo != "off" {
				b.PrintErr("Can't supply TLS key+cert and also ask for self-signed")
			}

			if opts.Cert == "" || opts.Key == "" {
				b.PrintErr("Must supply both TLS server key and certificate")
			}

			servingPair, err := tls.LoadX509KeyPair(opts.Cert, opts.Key)
			b.CheckErr(err)
			srvData.TlsServingCertPair = &servingPair
		}

		if opts.TLSAlgo != "off" {
			srvData.TlsServingSelfSign = true
			srvData.TlsServingCertPair, err = utils.GenSelfSignedCa(b.GetLogger(), opts.TLSAlgo)
			b.CheckErr(err)
		}

		if srvData.TlsServingSelfSign {
			op.CertSummary(codec.HeadFromCertificate(srvData.TlsServingCertPair), "serving CA")
		} else {
			// TODO print whole chain here (styler has a method for this, expose on op)
			op.CertSummary(codec.HeadFromCertificate(srvData.TlsServingCertPair), "serving")
		}
	}

	if opts.ClientCA != "" {
		if !srvData.TlsOn {
			b.PrintErr("Can't verify TLS client certs without serving TLS")
		}

		bytes, err := ioutil.ReadFile(opts.ClientCA)
		b.CheckErr(err)
		srvData.TlsClientCA, err = codec.ParseCertificate(bytes)
		b.CheckErr(err)

		op.CertSummary(srvData.TlsClientCA, "client CA")
	}

	if opts.JWTValidatePath != "" {
		bytes, err := ioutil.ReadFile(opts.JWTValidatePath)
		b.CheckErr(err)
		srvData.AuthJwtValidateKey, err = codec.ParsePublicKey(bytes)
		b.CheckErr(err)

		op.KeySummary(srvData.AuthJwtValidateKey, "JWT validation")
	}

	srv := &http.Server{
		Addr:              opts.ListenAddr,
		ReadHeaderTimeout: 120 * time.Second, // Time for reading request headers
		ReadTimeout:       120 * time.Second, // Time for reading request headers + body
		WriteTimeout:      120 * time.Second, // Time for writing response (headers + body?)
		IdleTimeout:       120 * time.Second, // Time between requests before the connection is dropped, when keep-alives are used.
		Handler:           loggingMux,
		// Called when the http server starts listening
		BaseContext: func(l net.Listener) context.Context {
			codec.ParseListener(l, srvData)
			op.Listen(srvData) // TODO obvs shouln't be here
			return context.Background()
		},
		// Called when the http server accepts an incoming connection
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// Note: ctx has a bunch of info under context-key "http-server"

			requestNo++ // Think everything is single-threaded...
			codec.ParseNetConn(c, requestNo, reqData)

			return ctx
		},
		// Called when an http server connection changes state
		ConnState: func(c net.Conn, cs http.ConnState) {
			b.Trace("HTTP server connection state change", "State", cs)
		},
	}

	if srvData.TlsOn {
		srv.TLSConfig = &tls.Config{
			ClientAuth: tls.RequestClientCert, // request but don't require. TODO when we verify them, this should be VerifyClientCertIfGiven
			/* Hooks in order they're called */
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				b.Trace("TLS ClientHello received")

				codec.ParseTlsClientHello(hi, reqData)

				return nil, nil // option to bail handshake or change TLSConfig
			},
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if srvData.TlsServingSelfSign {
					cert, err := utils.GenServingCert(b.GetLogger(), hi, srvData.TlsServingCertPair, opts.TLSAlgo)
					//op.CertSummary(codec.HeadFromCertificate(cert), "generated serving")
					return cert, err
				}
				return srvData.TlsServingCertPair, nil
			},
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				b.Trace("TLS built-in cert verification finished")
				return nil // can do extra cert verification and reject
			},
			VerifyConnection: func(cs tls.ConnectionState) error {
				b.Trace("TLS: all cert verification finished")

				codec.ParseTlsConnectionState(&cs, reqData)

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
