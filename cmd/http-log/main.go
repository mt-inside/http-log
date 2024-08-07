package main

/* TODO: all your proxy options. Do we really wanna be terminating SOCKS? Maybe we do. Should handle connect and connect-udp at least.
* - "reguular" TCP/UDP proxy - ie packet forwarder, static config to host:port
* - SOCKS - dynamic, target in plaintext
* - CONNECT - tcp only. target encrypted if you're over https
* - CONNECT-UDP - now an IETF standard (along with HTTP DATAGRAMs and Capsules etc)
*   - QUIC Datagrams - for sending data *unreliably* over quic, so that quic-in-quic doesn't do double recovery and double congestion control
*   - h2 datagrams atop that
* - [h2&h3] Extended CONNECT - what's this?
* - proxy protocol
*
* TODO: should serve its JWKS document over HTTP, in the proper .well-known/whatever place you'd expect to find it
* - optional, cause people might want that path logging instead
 */

// TODO: h3 test servers (more for p-c): google, youtube, cloudflare-quic.com

/* TODO: --who-am-i option, for the server startup and the response body to use envbin lib and print (if applicable):
* - cloud provider one-line info
* - k8s info, one line for CP, one for Node, one for Pod (with sidecar info)
* - one line ext IP info
 */

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/jessevdk/go-flags"
	"github.com/logrusorgru/aurora/v3"
	"github.com/mattn/go-isatty"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/scope"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/mt-inside/go-jwks"

	"github.com/mt-inside/http-log/internal/build"
	"github.com/mt-inside/http-log/internal/ctxt"
	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/extractor"
	"github.com/mt-inside/http-log/pkg/handlers"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/state"
	"github.com/mt-inside/http-log/pkg/utils"
	"github.com/mt-inside/http-log/pkg/zaplog"
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
var log = scope.Register("main", "logs from the main package")
var metricRequests = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "httplog_requests",
})

// TODO: cobra + viper(? - go-flags is really nice)
func main() {

	// do new logging
	// X * find all GetLogger, stored logs, passed logs & kill. Go until go mod tidy doesn't want to pull in logr/zapr
	// X * package-level log globals. Store in classes where they exist (enriching with instance-metadata)
	// X * stuff into ctxt where appropriates, pull out req no
	// X The OG place that accepts the http request cooks up a ctxt, with a timeout (cause we're now doing net i/o etc) - THIS IS CONN_CONTEXT!
	// X * put any request metadata that you want to appear as log pairs in there (conn no)
	// X * new up reqData and respData and put them in there (pointers) - we've had trouble with these objects being reused, this should cure that
	// X * extract it in ServeHTTP with r.Context(), and pass this into the tree of functions (the handler func is the root function) - this repalced logging etc
	// Config is a global, cause it's a singleton.
	// * BUT: people prolly shouldn't access it direct, they should access srvData, so leave it where it is
	// X srvData is a function of the http.Server, so stuff it in there - in via BaseContext, out via r.Context() - check!
	// X bios should have no log
	// X * look at where bios is: only main should be doing check&exit - libs should be logging (to iface) and returning errors
	// think about arch!
	// X * extractors should be dumb (just copy the right fields), to keep code simple fast readable
	// X * renderers should be dumb (so they don't duplicate logic) - they shouldn't be trying to parse things or checking any errors
	// * that leaves some stage in the middle where we parse&enrich. That currently happens in LogMiddle::ServeHTTP.
	// X think about renderer owning bios owning styler etc.
	// X * is there a point to bios now the log's gone?
	// think! We're aiming to get to the point of doing the pretty output.
	// * that output alone should be sufficient for the user - everything they need to know about the request, but not necc how we got there
	// * We log along the way. tet/telemetry's levels are good:
	//   * debug: help me understand the app's state, generating self-signed cert
	//   * info: something happened you might wanna know about, but it won't be in the end output (prolly very few of these, but eg all the stuff about fetching oidc, accepting connection)
	//   * error: something happened *that we can't gracefully recover from* - this is something that means we have to stop processing and you'll get an incomplete result at the end
	//   * note that we also deal with error objects a lot (like cert expired) - they don't stop us processing, they're just how that (exceptional) info is returned
	//     * We don't error-log these; we store them and render them later. Those fields are prolly best called "FooReason"
	// * To recap: we only print in
	//   * main: arg issues etc - print & quit. Bios helps alleviate the tedium of this
	//   * <intermediate> - no printing. Logging only. Any errors logged (if they mean we've had processing issues, AND we won't print them at the end) or saved, if they're error-typed info (eg your JWT is expired)
	//   * output: at this point things should be parsed, there should literaly be no errors to check for.
	// * We only panic when: assumptions are broken (if we ever hit a panic, we add error check & handle logic)

	defaultLogger := zaplog.New()
	scope.UseLogger(defaultLogger)

	/* == Parse and grok arguments == */

	argv := make([]string, len(os.Args))
	copy(argv, os.Args)

	var configOpts struct {
		ConfigFile string `long:"config-file"`
	}
	configParser := flags.NewParser(&configOpts, 0)
	configParser.UnknownOptionHandler = func(option string, arg flags.SplitArgument, args []string) ([]string, error) {
		// Do nothing, overriding the default handler, which prints "unknown arg" errors
		return []string{}, nil
	}
	_, err := configParser.ParseArgs(os.Args)
	if err == nil {
		f, err := os.ReadFile(configOpts.ConfigFile)
		if err == nil {
			argv = strings.Split(string(f), " ")
		}
	}

	var opts struct {
		// TODO: take timeout for all network ops (in here and the TLSConfig too) - https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/

		/* Admin */
		Verbosity string `short:"v" long:"verbosity" description:"log verbosity. Does not affect final output" choice:"none" choice:"error" choice:"info" choice:"debug" default:"error"`
		AdminAddr string `long:"admin-addr" description:"Listen address for the admin port eg 127.0.0.1:8081" default:":8081"`

		/* Network options */
		ListenAddr    string        `short:"a" long:"addr" description:"Listen address eg 0.0.0.0:8080" default:":8080"`
		HandleTimeout time.Duration `long:"timeout" description:"Timeout for each of request reading and response writing" default:"60s"`
		Timeout       time.Duration `long:"handle-timeout" description:"Timeout for network fetches used to encrich the output" default:"10s"`
		Http11        bool          `long:"http-11" description:"Force http/1.1 (disallow TLS ALPN negotiation of http2)"`

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
		JWTValidatePath string `short:"j" long:"jwt-validate-key" description:"Path to a [JWK[S],PEM]-encoded (determined by file extension) [rsa,ecdsa,ed25519] public key used to validate JWTs"`

		/* Output options */
		Output string `short:"o" long:"output" description:"Log output format" choice:"auto" choice:"pretty" choice:"text" choice:"json" default:"auto"`
		output.RendererOpts
	}

	_, err = flags.ParseArgs(&opts, argv)
	if err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		panic(err)
	}

	switch strings.ToLower(opts.Verbosity) {
	case "debug":
		scope.SetAllScopes(telemetry.LevelDebug)
	case "info":
		scope.SetAllScopes(telemetry.LevelInfo)
	case "error":
		scope.SetAllScopes(telemetry.LevelError)
	case "none":
		scope.SetAllScopes(telemetry.LevelNone)
	default:
		panic(fmt.Errorf("impossible log level %s", opts.Verbosity))
	}

	if opts.Output == "auto" {
		if isatty.IsTerminal(os.Stdout.Fd()) {
			opts.Output = "pretty"
		} else {
			opts.Output = "json"
		}
	}

	// ie defaults are: -l -m
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

	// We make one styler here (which is utility functions) and construct Bios and Renderer over it.
	// However, they're very different. Renderer outputs at the end. Bios is used here to remove the tedium of pre-flight checks.
	var b bios.Bios
	var op output.Renderer
	switch opts.Output {
	case "text":
		s := output.NewTtyStyler(aurora.NewAurora(false)) // no color
		b = bios.NewTtyBios(s)
		op = output.NewTtyRenderer(s, opts.RendererOpts)
	case "pretty":
		s := output.NewTtyStyler(aurora.NewAurora(true)) // color
		// TODO: verbosity option
		b = bios.NewTtyBios(s)
		op = output.NewTtyRenderer(s, opts.RendererOpts)
	case "json":
		// TODO: verbosity option
		//l := usvc.GetLogger(false, 0)
		//b = output.NewLogBios(l)
		//op = output.NewLogRenderer(l) //FIXME

		// for now
		s := output.NewTtyStyler(aurora.NewAurora(false))
		b = bios.NewTtyBios(s)
		op = output.NewTtyRenderer(s, opts.RendererOpts)
	default:
		panic(errors.New("bottom"))
	}

	b.Version()

	srvData := state.NewDaemonData()

	// TODO: mutex status/reply vs passtrhoughURL vs passthroughAuto - no more than 1. If none are set, use the defaults for status & response
	var actionMux http.Handler = handlers.NewResponseHandler(opts.Status, opts.ResponseFormat)
	if opts.PassthroughURL != "" || opts.PassthroughAuto {
		var url *url.URL = nil
		if opts.PassthroughURL != "" {
			url, err = url.Parse(opts.PassthroughURL)
			b.Unwrap(err)
		}
		actionMux = handlers.NewPassthroughHandler(url, srvData)
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
			srvData.TlsServingCertPair, err = utils.GenSelfSignedCa(context.Background(), opts.TLSAlgo, build.Name)
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
		switch filepath.Ext(opts.JWTValidatePath) {
		case ".jwks":
			keys, err := jwks.JWKS2KeysMap(bytes)
			b.Unwrap(err)
			for kid, key := range keys {
				srvData.AuthJwtValidateKey = key
				if len(keys) > 1 {
					b.PrintWarn(fmt.Sprintf("JWKS contains >1 key; randomly using key id %s", kid))
				}
				break
			}
		case ".jwk":
			key, err := jwks.JWK2Key(bytes)
			b.Unwrap(err)
			srvData.AuthJwtValidateKey = key
		default:
			srvData.AuthJwtValidateKey, err = codec.ParsePublicKey(bytes)
			b.Unwrap(err)
		}
	}

	// Admin port. TODO factor out
	go func() {
		startTime := time.Now().UTC()

		r := http.NewServeMux()
		r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			j, _ := json.Marshal(map[string]string{"health": "ok", "name": build.Name, "version": build.Version, "started": fmt.Sprintf("%v", startTime), "uptime": fmt.Sprintf("%v", time.Since(startTime))})
			_, _ = w.Write(j)
		})
		r.HandleFunc("/quitquitquit", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("quitting"))
			os.Exit(0)
		})
		r.HandleFunc("/cacert", func(w http.ResponseWriter, r *http.Request) {
			// Outputs as x.509 in DER in PEM
			// - Go doesn't support rendering PKCS#12 anyway
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: srvData.TlsServingCertPair.Certificate[0],
			}
			b.Unwrap(pem.Encode(w, block))
		})
		r.Handle("/metrics", promhttp.Handler())

		srv := &http.Server{
			Addr:    opts.AdminAddr,
			Handler: r,
		}
		_ = srv.ListenAndServe()

		// TODO: gRPC admin port, serving at least gRPC health proto
	}()

	loggingMux := handlers.NewLogMiddle(
		actionMux,
	)

	lis, err := net.Listen("tcp", opts.ListenAddr)
	b.Unwrap(err)

	proxyLis := &proxyproto.Listener{
		Listener:          lis,
		ReadHeaderTimeout: opts.HandleTimeout,
	}
	defer proxyLis.Close()

	srv2 := &http2.Server{
		IdleTimeout: 0,
	}

	srv := &http.Server{
		Addr:              opts.ListenAddr,                                                          // TODO: doesn't need to be here because we make our own net.lis?
		ReadHeaderTimeout: opts.HandleTimeout,                                                       // Time for reading request headers (docs are unclear but seemingly subsumed into ReadTimeout)
		ReadTimeout:       opts.HandleTimeout,                                                       // Time for reading request headers + body
		WriteTimeout:      opts.HandleTimeout,                                                       // Time for writing response (headers + body)
		IdleTimeout:       0,                                                                        // Time between requests before the connection is dropped, when keep-alives are used.
		Handler:           utils.Ternary(opts.Http11, loggingMux, h2c.NewHandler(loggingMux, srv2)), // This lib is tres useful. It handles upgrades from h1 using `Upgrade: h2c`, and also makes immediate-h2 work, I guess by spotting the PRI method and hijacking. It even arranges for BaseContext and ConnContext to be called, which I couldn't figure out driving http2 manually
		// Called when the http server starts listening.
		// Not called by http2.ServeCon
		BaseContext: func(l net.Listener) context.Context {
			extractor.NetListener(l, srvData)

			// Now we're listening, print server info
			op.ListenInfo(srvData)

			ctx := context.Background()
			ctx = ctxt.SrvDataToContext(ctx, srvData)

			return ctx
		},
		// Called when the http server accepts an incoming connection
		// Not called by h2.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// TODO: ctx has a bunch of info under context-key "http-server"

			reqData := state.NewRequestData()
			respData := state.NewResponseData()

			requestNo++ // Think everything is single-threaded... TODO really can't assume that.
			metricRequests.Set(float64(requestNo))

			ctx = telemetry.KeyValuesToContext(ctx, "request", requestNo)
			log := log.With(telemetry.KeyValuesFromContext(ctx)...)
			log.Info("Accepting tcp connection") // TODO: these needs to use "tcp" / "http"-scoped loggers. The fact they don't have them tells you they shouldn't be here, prolly should in extractors?
			extractor.NetConn(c, requestNo, reqData)

			ctx = ctxt.ReqDataToContext(ctx, reqData)
			ctx = ctxt.RespDataToContext(ctx, respData)

			toHackStore(c, ctx)

			return ctx
		},
		// Called when an http server connection changes state
		// Called by h2.
		ConnState: func(c net.Conn, cs http.ConnState) {
			ctx, log := fromHackStore(c, log)

			log.Info("Connection state change", "state", cs)

			// FIXME: h2, Envoy(h1), etc hold connections open, so we prolly need to hook IDLE to print
			// - indeed, print-cert-repeating over h2 just has the conn go active,idle,active,etc. All seem like the same reqNo. Never get printed
			// need to detect conn re-use somehow, and bump reqNo (and make new structs etc) on transition to active (but re-use the tcp info from the conn going to new omg)
			// - but it goes idle >1 time. When? Seen: h2c's h2 upgrade (PRI or h1:Upgrade); TLS handshake
			// when this is fixed, can put istio-demo back to h2 (appProto http2, h2UpgradePolicy)
			// Sketch solution:
			// - fact: we print on conn close (ie at the transport layer) so we catch all requests, even if they don't make it very far
			// - print at the end of the http handler (think we used to do this). This will catch a lot of cases, including http error-codes
			// - also print on conn_closed, to catch things that have error'd before http handler got to see them (eg TLS handshake).
			//   - thesis is that everything that didn't make it to the http handler is enough of an error to cause the connection to be closed (cause it's tcp and below, and that only happens once per conn, so without it there can be no conn)
			//   - in the conn_close handler, check the connection number and ignore it if we've already printed it
			// - as a backstop, set idle timeout waay shorter (rather than running the timer ourself) - need to check if that actually works, or if h2 keepalives reset it
			//   - can't be too short, else we'll time out slow clients
			// Sketch arch:
			// - have a connection_manager class (owns hackStore)
			// - gets all the conn state change events, plus calls from eg http handler saying done
			//   - make these done(stage String) (eg done("http")), err(stage) eg err("tls")
			// - just log the events, and print the connection table for now, to see what's going on
			// - this is actually a RequestManager
			//   - we naievly assumed that a request ending is signaled by a connection ending
			//   - track connections, and requests, and assign reqs to conns
			//   - conn closing closes all the requests under it
			//   - req_new is gonna be like the tls hi handler, or http handler for non-tls?
			//   - req_err is gonna be... all error handling paths?
			//   - req_done is gonna be end of the http handler? which one? log middle? whatever's given to stdlib. Think can just add to log_moddle, or might wanna wrap again
			//     - how catch all errors in an http handler?
			if cs == http.StateClosed {
				srvData := ctxt.SrvDataFromContext(ctx)
				reqData := ctxt.ReqDataFromContext(ctx)
				respData := ctxt.RespDataFromContext(ctx)
				op.Output(srvData, reqData, respData)

				delete(hackStore, c.RemoteAddr())
				log.Debug("Connection closed; removing entry from hackStore", "remoteAddr", c.RemoteAddr())
			}
			// FIXME: for now we over-print, better than under-printing
			if cs == http.StateIdle {
				srvData := ctxt.SrvDataFromContext(ctx)
				reqData := ctxt.ReqDataFromContext(ctx)
				respData := ctxt.RespDataFromContext(ctx)
				op.Output(srvData, reqData, respData)
			}
		},
	}

	if srvData.TlsOn {
		srv.TLSConfig = &tls.Config{
			/* Hooks in order they're called */
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				ctx, log := fromHackStore(hi.Conn, log)

				log.Info("TLS ClientHello received, proposing TLS config")

				reqData := ctxt.ReqDataFromContext(ctx)

				extractor.TlsClientHello(hi, reqData)

				// Close over this req/respData
				cfg := &tls.Config{
					NextProtos: utils.Ternary(opts.Http11, nil, []string{"h2", "http/1.1"}), // Because we're providing our own tls.Config, this is by default empty, so h1.1 will be negotiated. So we manually send this.
					ClientAuth: tls.RequestClientCert,                                       // request but don't require. TODO when we verify them, this should be VerifyClientCertIfGiven
					GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
						log.Info("TLS Asked for serving cert")
						if srvData.TlsServingSelfSign {
							cert, err := utils.GenServingCert(ctx, hi, srvData.TlsServingCertPair, opts.TLSAlgo, build.Name)
							if err == nil {
								reqData.TlsNegServerCert = cert
							}
							return cert, err
						}

						log.Info("Returning configured serving cert")
						return srvData.TlsServingCertPair, nil
					},
					VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
						log.Info("Built-in cert verification finished (no-op)")
						return nil // can do extra cert verification and reject
					},
					VerifyConnection: func(cs tls.ConnectionState) error {
						log.Info("Connection parameter validation")

						extractor.TlsConnectionState(&cs, reqData)

						return nil // can inspect all connection and TLS info and reject
					},
				}

				return cfg, nil
			},
			// Have to provide a non-nil GetCertificate(), else ListenAndServeTLS() will try to open the paths you give it (and we have to give "")
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				panic("I should never be called; TLS config should be overwritten by this point")
			},
		}
		b.Unwrap(srv.ServeTLS(proxyLis, "", ""))
		log.Info("Server shutting down")
	} else {
		b.Unwrap(srv.Serve(proxyLis))
		// The h2c library is magic and handles h2/plaintext, even those without prior Upgrade requests.
		// However if you did wanna do h2 manually, this is how (since I went to the effort of working it out):
		// for {
		// 	conn, err := proxyLis.Accept()
		// 	b.Unwrap(err)

		// 	// Have to do BaseContext and ConnContext in here. Neither are called by h2.
		// 	ctx := context.Background()
		// 	ctx = ctxt.SrvDataToContext(ctx, srvData)
		// 	var cancel context.CancelFunc
		// 	ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		// 	reqData := state.NewRequestData()
		// 	respData := state.NewResponseData()

		// 	requestNo++
		// 	ctx = telemetry.KeyValuesToContext(ctx, "request", requestNo)
		// 	log := log.With(telemetry.KeyValuesFromContext(ctx)...)
		// 	log.Info("Accepting tcp connection")
		// 	extractor.NetConn(conn, requestNo, reqData)

		// 	ctx = ctxt.ReqDataToContext(ctx, reqData)
		// 	ctx = ctxt.RespDataToContext(ctx, respData)
		// 	ctx = ctxt.CtxCancelToContext(ctx, cancel)
		// 	toHackStore(conn, ctx)
		// 	go srv2.ServeConn(
		// 		conn,
		// 		&http2.ServeConnOpts{
		// 			BaseConfig: srv,
		// 			Context:    ctx,
		// 		},
		// 	)
		// }
		log.Info("Server shutting down")
	}
}

var hackStore = map[net.Addr]context.Context{}

func toHackStore(c net.Conn, ctx context.Context) {
	// TODO lock me
	if _, found := hackStore[c.RemoteAddr()]; found {
		panic("Assumption broken: remoteAddr reused")
		// TODO: remove conns from the map when their state changes to closed
	}
	hackStore[c.RemoteAddr()] = ctx
}
func fromHackStore(c net.Conn, log telemetry.Logger) (context.Context, telemetry.Logger) {
	// TODO lock me
	ctx, found := hackStore[c.RemoteAddr()]
	if !found {
		panic("Couldn't find req/respData in hack store")
	}
	logOut := log.With(telemetry.KeyValuesFromContext(ctx)...)

	return ctx, logOut
}
