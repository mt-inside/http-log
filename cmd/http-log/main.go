package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	"github.com/mt-inside/http-log/pkg/extractor"
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

var requestNo uint64

// TODO: cobra + viper(? - go-flags is really nice)
func main() {

	/* == Parse and grok arguments == */

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

		/* Output options */
		Output string `short:"o" long:"output" description:"Log output format" choice:"auto" choice:"pretty" choice:"text" choice:"json" default:"auto"`
		output.RendererOpts
	}

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
	var op output.Renderer
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

	loggingMux := handlers.NewLogMiddle(
		b,
		op,
		opts.RendererOpts,
		reqData,
		respData,
		srvData,
		actionMux,
	)

	srv := &http.Server{
		Addr:              opts.ListenAddr,
		ReadHeaderTimeout: 120 * time.Second, // Time for reading request headers
		ReadTimeout:       120 * time.Second, // Time for reading request headers + body
		WriteTimeout:      120 * time.Second, // Time for writing response (headers + body?)
		IdleTimeout:       120 * time.Second, // Time between requests before the connection is dropped, when keep-alives are used.
		Handler:           loggingMux,
		// Called when the http server starts listening
		BaseContext: func(l net.Listener) context.Context {
			extractor.NetListener(l, srvData)

			// Now we're listening, print server info
			op.ListenInfo(srvData)

			return context.Background()
		},
		// Called when the http server accepts an incoming connection
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// Note: ctx has a bunch of info under context-key "http-server"

			requestNo++ // Think everything is single-threaded...
			b.TraceWithName("tcp", "Accepting connection", "number", requestNo)
			extractor.NetConn(c, requestNo, reqData)

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

				extractor.TlsClientHello(hi, reqData)

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

				extractor.TlsConnectionState(&cs, reqData)

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
