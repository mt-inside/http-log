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

	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/handlers"
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
	Version()
	ListenInfo(d *state.DaemonData)

	// TODO: then start moving things around, eg Hops with connection, HSTS with TLS (is a print-cert thing but that needs the same treatment)
	TransportSummary(d *state.RequestData)
	TransportFull(d *state.RequestData)
	TLSNegSummary(d *state.RequestData)
	TLSNegFull(r *state.RequestData, s *state.DaemonData)
	TLSAgreedSummary(r *state.RequestData, s *state.DaemonData)
	TLSAgreedFull(r *state.RequestData, s *state.DaemonData)
	HeadSummary(d *state.RequestData)
	HeadFull(d *state.RequestData)
	BodySummary(d *state.RequestData)
	BodyFull(d *state.RequestData)
	ResponseSummary(d *state.ResponseData)
	ResponseFull(d *state.ResponseData)
}

var requestNo uint64

// TODO: move out of this file
type logMiddle struct {
	b        output.Bios
	op       renderer
	reqData  *state.RequestData
	respData *state.ResponseData
	srvData  *state.DaemonData
	next     http.Handler
}

func (lm logMiddle) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	/* Record request info */

	codec.ParseHttpRequest(r, lm.srvData, lm.reqData)

	now := time.Now()
	var err error
	lm.reqData.HttpBody, err = io.ReadAll(r.Body)
	lm.reqData.HttpBodyTime = &now
	lm.b.Unwrap(err) // TODO: shouldn't kill things, should be saved in reqData (NB: req, not resp here) and printed later

	/* Next */

	lm.next.ServeHTTP(w, r)

	/* Request-response is over: print */
	lm.output()
}

func (lm logMiddle) output() {

	if opts.ConnectionSummary {
		lm.op.TransportSummary(lm.reqData)
	} else if opts.ConnectionFull {
		lm.op.TransportFull(lm.reqData)
	}

	if lm.srvData.TlsOn {
		if opts.NegotiationFull {
			lm.op.TLSNegFull(lm.reqData, lm.srvData)
		} else if opts.NegotiationSummary {
			lm.op.TLSNegSummary(lm.reqData)
		}
		if opts.TLSFull {
			lm.op.TLSAgreedFull(lm.reqData, lm.srvData)
		} else if opts.TLSSummary {
			// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
			lm.op.TLSAgreedSummary(lm.reqData, lm.srvData)
		}
	}

	if opts.HeadFull {
		lm.op.HeadFull(lm.reqData)
	} else if opts.HeadSummary {
		// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
		lm.op.HeadSummary(lm.reqData)
	}

	// Print only if the method would traditionally have a body
	if (opts.BodyFull || opts.BodySummary) && (lm.reqData.HttpMethod == http.MethodPost || lm.reqData.HttpMethod == http.MethodPut || lm.reqData.HttpMethod == http.MethodPatch) {
		if opts.BodyFull {
			lm.op.BodyFull(lm.reqData)
		} else if opts.BodySummary {
			lm.op.BodySummary(lm.reqData)
		}
	}

	if opts.ResponseFull {
		lm.op.ResponseFull(lm.respData)
	} else if opts.ResponseSummary {
		lm.op.ResponseSummary(lm.respData)
	}
}

// TODO: move into main. Anything preventing that is wrong
var opts struct {
	// TODO: take timeout for all network ops (in here and the TLSConfig too) - https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
	/* Network options */
	ListenAddr string        `short:"a" long:"addr" description:"Listen address eg 127.0.0.1:8080" default:":8080"`
	Timeout    time.Duration `long:"timeout" description:"Timeout for each individual network operation"`

	/* Response options */
	Status          int    `short:"s" long:"status" description:"HTTP status code to return" default:"200"`
	ResponseFormat  string `short:"f" long:"response-format" description:"HTTP response body format" choice:"none" choice:"text" choice:"json" choice:"xml" default:"text"`
	PassthroughAuto bool   `short:"P" long:"passthrough-auto" description:"Proxy request to the URL in the received request"`
	PassthroughURL  string `short:"p" long:"passthrough-url" description:"Proxy request to given URL" default:""`

	/* TLS and validation */
	Cert            string `short:"c" long:"cert" optional:"yes" description:"Path to TLS server certificate. Setting this implies serving https"`
	Key             string `short:"k" long:"key" optional:"yes" description:"Path to TLS server key. Setting this implies serving https"`
	TLSAlgo         string `short:"K" long:"self-signed-tls" choice:"off" choice:"rsa" choice:"ecdsa" choice:"ed25519" default:"off" optional:"yes" optional-value:"rsa" description:"Generate and present a self-signed TLS certificate? No flag / -k=off: plaintext. -k: TLS with RSA certs. -k=foo TLS with $foo certs"`
	ClientCA        string `short:"C" long:"ca" optional:"yes" description:"Path to TLS client CA certificate"`
	JWTValidatePath string `short:"j" long:"jwt-validate-key" description:"Path to a PEM-encoded [rsa,ecdsa,ed25519] public key used to validate JWTs"`

	/* Logging settings */
	Output             string `short:"o" long:"output" description:"Log output format" choice:"auto" choice:"pretty" choice:"text" choice:"json" default:"auto"`
	ConnectionSummary  bool   `short:"l" long:"connection" description:"Print summary of connection (eg TCP) information"`
	ConnectionFull     bool   `short:"L" long:"connection-full" description:"Print all connection (eg TCP) information"`
	NegotiationSummary bool   `short:"n" long:"negotiation" description:"Print transport (eg TLS) setup negotiation summary, notable the SNI ServerName being requested"`
	NegotiationFull    bool   `short:"N" long:"negotiation-full" description:"Print transport (eg TLS) setup negotiation values, ie what both sides offer to support"`
	TLSSummary         bool   `short:"t" long:"tls" description:"Print important agreed TLS parameters"`
	TLSFull            bool   `short:"T" long:"tls-full" description:"Print all agreed TLS parameters"`
	HeadSummary        bool   `short:"m" long:"head" description:"Print important HTTP request metadata"`
	HeadFull           bool   `short:"M" long:"head-full" description:"Print all HTTP request metadata"`
	BodySummary        bool   `short:"b" long:"body" description:"Print truncated HTTP request body"`
	BodyFull           bool   `short:"B" long:"body-full" description:"Print full HTTP request body"`
	ResponseSummary    bool   `short:"r" long:"response" description:"Print summary of HTTP response"`
	ResponseFull       bool   `short:"R" long:"response-full" description:"Print full information about HTTP response"`
}

// TODO: cobra + viper(? - go-flags is really nice)
func main() {

	/* == Parse and grok arguments == */

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
		b = output.NewTtyBios(s, 10)
		op = output.NewTtyRenderer(s)
	case "pretty":
		s := output.NewTtyStyler(aurora.NewAurora(true)) // color
		// TODO: verbosity option
		b = output.NewTtyBios(s, 10)
		op = output.NewTtyRenderer(s)
	case "json":
		// TODO: verbosity option
		//l := usvc.GetLogger(false, 0)
		//b = output.NewLogBios(l)
		//op = output.NewLogRenderer(l) //FIXME

		// for now
		s := output.NewTtyStyler(aurora.NewAurora(false))
		b = output.NewTtyBios(s, 0)
		op = output.NewTtyRenderer(s)
	default:
		panic(errors.New("bottom"))
	}

	op.Version()

	if !opts.ConnectionSummary && !opts.ConnectionFull &&
		!opts.NegotiationSummary && !opts.NegotiationFull &&
		!opts.TLSSummary && !opts.TLSFull &&
		!opts.HeadSummary && !opts.HeadFull &&
		!opts.BodySummary && !opts.BodyFull &&
		!opts.ResponseSummary && !opts.ResponseFull {
		opts.ConnectionSummary = true
		opts.HeadSummary = true
		if opts.PassthroughURL != "" || opts.PassthroughAuto {
			opts.ResponseSummary = true
		}
	}

	srvData := state.NewDaemonData()
	reqData := state.NewRequestData()
	respData := state.NewResponseData()

	// TODO: mutex status/reply vs passtrhoughURL vs passthroughAuto - no more than 1. If none are set, use the defaults for status & response
	var actionMux http.Handler = handlers.NewResponseHandler(opts.Status, opts.ResponseFormat, respData)
	if opts.PassthroughURL != "" || opts.PassthroughAuto {
		var url *url.URL = nil
		if opts.PassthroughURL != "" {
			url, err = url.Parse(opts.PassthroughURL)
			b.Unwrap(err)
		}
		actionMux = handlers.NewPassthroughHandler(url, srvData, reqData, respData)
	}

	srvData.TlsOn = false
	if opts.Cert != "" || opts.Key != "" || opts.TLSAlgo != "off" {
		srvData.TlsOn = true

		if opts.Cert != "" || opts.Key != "" {
			if opts.TLSAlgo != "off" {
				b.PrintErr("Can't supply TLS key+cert and also ask for self-signed")
				os.Exit(1)
			}

			if opts.Cert == "" || opts.Key == "" {
				b.PrintErr("Must supply both TLS server key and certificate")
				os.Exit(1)
			}

			servingPair, err := tls.LoadX509KeyPair(opts.Cert, opts.Key)
			b.Unwrap(err)
			srvData.TlsServingCertPair = &servingPair
		}

		if opts.TLSAlgo != "off" {
			srvData.TlsServingSelfSign = true
			srvData.TlsServingCertPair, err = utils.GenSelfSignedCa(b.GetLogger(), opts.TLSAlgo)
			b.Unwrap(err)
		}
	}

	if opts.ClientCA != "" {
		if !srvData.TlsOn {
			b.PrintErr("Can't verify TLS client certs without serving TLS")
			os.Exit(1)
		}

		bytes, err := os.ReadFile(opts.ClientCA)
		b.Unwrap(err)
		srvData.TlsClientCA, err = codec.ParseCertificate(bytes)
		b.Unwrap(err)
	}

	if opts.JWTValidatePath != "" {
		bytes, err := os.ReadFile(opts.JWTValidatePath)
		b.Unwrap(err)
		srvData.AuthJwtValidateKey, err = codec.ParsePublicKey(bytes)
		b.Unwrap(err)
	}

	loggingMux := &logMiddle{
		reqData:  reqData,
		respData: respData,
		srvData:  srvData,
		b:        b,
		op:       op,
		next:     actionMux,
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

			// Now we're listening, print server info
			op.ListenInfo(srvData)

			return context.Background()
		},
		// Called when the http server accepts an incoming connection
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// Note: ctx has a bunch of info under context-key "http-server"

			requestNo++ // Think everything is single-threaded...
			b.TraceWithName("tcp", "Accepting connection", "number", requestNo)
			codec.ParseNetConn(c, requestNo, reqData)

			return ctx
		},
		// Called when an http server connection changes state
		ConnState: func(c net.Conn, cs http.ConnState) {
			b.TraceWithName("http", "Connection state change", "state", cs)
		},
	}

	if srvData.TlsOn {
		srv.TLSConfig = &tls.Config{
			ClientAuth: tls.RequestClientCert, // request but don't require. TODO when we verify them, this should be VerifyClientCertIfGiven
			/* Hooks in order they're called */
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				b.TraceWithName("tls", "ClientHello received, proposing TLS config")

				codec.ParseTlsClientHello(hi, reqData)

				// TODO: is TLSConfig how we stop it suggesting ciphers/whatever so old that Go's own client rejects them?
				return nil, nil // option to bail handshake or change TLSConfig
			},
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				b.TraceWithName("tls", "Asked for serving cert")
				if srvData.TlsServingSelfSign {
					b.TraceWithName("tls", "Generating self-signed serving cert")
					cert, err := utils.GenServingCert(b.GetLogger(), hi, srvData.TlsServingCertPair, opts.TLSAlgo)
					if err == nil {
						reqData.TlsNegServerCert = cert
					}
					return cert, err
				}

				b.TraceWithName("tls", "Returning configured serving cert")
				return srvData.TlsServingCertPair, nil
			},
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				b.TraceWithName("tls", "Built-in cert verification finished (no-op)")
				return nil // can do extra cert verification and reject
			},
			VerifyConnection: func(cs tls.ConnectionState) error {
				b.TraceWithName("tls", "Connection parameter validation")

				codec.ParseTlsConnectionState(&cs, reqData)

				return nil // can inspect all connection and TLS info and reject
			},
		}
		b.Unwrap(srv.ListenAndServeTLS("", ""))
		b.Trace("Server shutting down")
	} else {
		b.Unwrap(srv.ListenAndServe())
		b.Trace("Server shutting down")
	}
}
