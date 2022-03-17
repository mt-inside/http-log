package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/jessevdk/go-flags"
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

type outputter interface {
	TLSNegSummary(cs *tls.ClientHelloInfo)
	TLSNegFull(cs *tls.ClientHelloInfo)
	TransportSummary(cs *tls.ConnectionState)
	TransportFull(cs *tls.ConnectionState)
	HeadSummary(proto, method, host, ua string, url *url.URL, respCode int)
	HeadFull(r *http.Request, respCode int)
	AuthSummary(r *http.Request)
	AuthFull(r *http.Request)
	BodySummary(contentType string, contentLength int64, body []byte)
	BodyFull(contentType string, contentLength int64, body []byte)
}

var requestNo uint

type logMiddle struct {
	log    logr.Logger
	next   http.Handler
	output outputter
	caPair *tls.Certificate
}

func (lm logMiddle) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	/* Headers */

	userAgent, _ := getHeader(r, "User-Agent")
	if opts.HeadFull {
		lm.output.HeadFull(r, opts.Status)
		lm.output.AuthFull(r)
	} else if opts.HeadSummary {
		// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
		lm.output.HeadSummary(r.Proto, r.Method, r.Host, userAgent, r.URL, opts.Status)
		lm.output.AuthSummary(r)
	}

	/* Body */

	contentType, _ := getHeader(r, "Content-Type")
	// Print only if the method would traditionally have a body, or one has been sent
	if (opts.BodyFull || opts.BodySummary) && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
		bs, err := io.ReadAll(r.Body)
		if err != nil {
			lm.log.Error(err, "failed to get body")
		}

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
	ListenAddr         string `short:"a" long:"addr" description:"Listen address eg 127.0.0.1:8080" default:":8080"`
	TLSAlgo            string `short:"k" long:"tls" choice:"off" choice:"rsa" choice:"ecdsa" choice:"ed25519" default:"off" optional:"yes" optional-value:"rsa" description:"Generate and present a self-signed TLS certificate? No flag / -k=off: plaintext. -k: TLS with RSA certs. -k=foo TLS with $foo certs"`
	NegotiationSummary bool   `short:"n" long:"negotiation" description:"Print transport (eg TLS) setup negotiation summary, notable the SNI ServerName being requested"`
	NegotiationFull    bool   `short:"N" long:"negotiation-full" description:"Print transport (eg TLS) setup negotiation values, ie what both sides offer to support"`
	TransportSummary   bool   `short:"t" long:"transport" description:"Print important agreed transport (eg TLS) parameters"`
	TransportFull      bool   `short:"T" long:"transport-full" description:"Print all agreed transport (eg TLS) parameters"`
	HeadSummary        bool   `short:"m" long:"head" description:"Print important header values"`
	HeadFull           bool   `short:"M" long:"head-full" description:"Print entire request head"`
	BodySummary        bool   `short:"b" long:"body" description:"Print truncated body"`
	BodyFull           bool   `short:"B" long:"body-full" description:"Print full body"`
	Output             string `short:"o" long:"output" description:"Log output format" choice:"auto" choice:"pretty" choice:"json" default:"auto"`
	Response           string `short:"r" long:"response" description:"HTTP response body format" choice:"none" choice:"text" choice:"json" choice:"xml" default:"text"`
	Status             int    `short:"s" long:"status" description:"Http status code to return" default:"200"`
}

func main() {

	log := usvc.GetLogger(false)

	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}
	if !opts.TransportSummary && !opts.TransportFull && !opts.HeadSummary && !opts.HeadFull && !opts.BodySummary && !opts.BodyFull {
		opts.HeadSummary = true
	}

	log.Info("http-log v0.5")

	var op outputter
	switch opts.Output {
	case "text":
		op = output.NewTty(log, false) // no color
	case "pretty":
		op = output.NewTty(log, true) // color
	case "json":
		op = output.NewLog(log)
	case "auto":
		if isatty.IsTerminal(os.Stdout.Fd()) {
			op = output.NewTty(log, true)
		} else {
			op = output.NewLog(log)
		}
	default:
		panic(errors.New("bottom"))
	}

	/*
		TODO
		* make a client that prints (in color) http server details - canonical DNS name, ip, cert details inc sans, server header, ALPN details, based on print-cert
	*/

	handler := func(w http.ResponseWriter, r *http.Request) {

		bytes, mime := codec.BytesAndMime(opts.Status, codec.GetBody(), opts.Response)
		w.Header().Set("Content-Type", mime)
		w.WriteHeader(opts.Status)
		_, err = w.Write(bytes)
		if err != nil {
			panic(err)
		}
	}

	mux := &http.ServeMux{}
	mux.HandleFunc("/", handler)
	loggingMux := &logMiddle{
		log:    log,
		next:   mux,
		output: op,
	}

	if opts.TLSAlgo != "off" {
		loggingMux.caPair, err = utils.GenSelfSignedCa(loggingMux.log, opts.TLSAlgo)
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
				log.Info("HTTP server listening", "Addr", l.Addr(), "transport", "plaintext")
			default: // *tls.listener assumed
				log.Info("HTTP server listening", "Addr", l.Addr(), "transport", "tls", "algo", opts.TLSAlgo)
			}
			return context.Background()
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			requestNo++ // Think everything is single-threaded...
			log.V(1).Info("L4 connection accepted", "RequestCount", requestNo, "from", c.RemoteAddr())

			return ctx
		},
		ConnState: func(c net.Conn, cs http.ConnState) {
			log.V(1).Info("HTTP server connection state change", "State", cs)
		},
	}

	if opts.TLSAlgo != "off" {
		srv.TLSConfig = &tls.Config{
			/* Hooks in order they're called */
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				log.V(1).Info("TLS ClientHello received")

				if opts.NegotiationFull {
					op.TLSNegFull(hi)
				} else if opts.NegotiationSummary {
					op.TLSNegSummary(hi)
				}

				return nil, nil // option to bail handshake or change TLSConfig
			},
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return utils.GenServingCert(loggingMux.log, hi, loggingMux.caPair, opts.TLSAlgo)
			},
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				log.V(1).Info("TLS built-in cert verification finished")
				return nil // can do extra cert verification and reject
			},
			VerifyConnection: func(cs tls.ConnectionState) error {
				log.V(1).Info("TLS: all cert verification finished")

				if opts.TransportFull {
					op.TransportFull(&cs)
				} else if opts.TransportSummary {
					// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
					op.TransportSummary(&cs)
				}

				return nil // can inspect all connection and TLS info and reject
			},
		}
		log.Error(srv.ListenAndServeTLS("", ""), "Shutting down")
	} else {
		log.Error(srv.ListenAndServe(), "Shutting down")
	}
}

func getHeader(r *http.Request, h string) (ret string, ok bool) {
	hs := r.Header[h]
	if len(hs) >= 1 {
		ret = hs[0]
		ok = true
	} else {
		ret = fmt.Sprintf("<no %s>", h)
		ok = false
	}

	return
}
