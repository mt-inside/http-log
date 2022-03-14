package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/jessevdk/go-flags"
	"github.com/mattn/go-isatty"
	"github.com/mt-inside/go-usvc"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

/* TODO:
* combine code with lb-checker - stuff to render certs, tls.connectionstate, etc
* if present, print
*   credentials
 */

type outputter interface {
	TLSNegFull(log logr.Logger, cs *tls.ClientHelloInfo)
	TransportSummary(log logr.Logger, cs *tls.ConnectionState)
	TransportFull(log logr.Logger, cs *tls.ConnectionState)
	HeadSummary(log logr.Logger, proto, method, host, ua string, url *url.URL, respCode int)
	HeadFull(log logr.Logger, r *http.Request, respCode int)
	BodySummary(log logr.Logger, contentType string, contentLength int64, method string, body []byte)
	BodyFull(log logr.Logger, contentType string, r *http.Request, body []byte)
}

var requestNo uint

type logMiddle struct {
	log        logr.Logger
	next       http.Handler
	output     outputter
	certSerial int64
	caPair     *tls.Certificate
}

func (lm logMiddle) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	/* Headers */

	userAgent, _ := getHeader(r, "User-Agent")
	if opts.HeadFull {
		lm.output.HeadFull(lm.log, r, opts.Status)
	} else if opts.HeadSummary {
		// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
		lm.output.HeadSummary(lm.log, r.Proto, r.Method, r.Host, userAgent, r.URL, opts.Status)
	}

	/* Body */

	contentType, _ := getHeader(r, "Content-Type")
	if opts.BodyFull || opts.BodySummary {
		bs, err := io.ReadAll(r.Body)
		if err != nil {
			lm.log.Error(err, "failed to get body")
		}

		if opts.BodyFull {
			lm.output.BodyFull(lm.log, contentType, r, bs)
		} else if opts.BodySummary {
			lm.output.BodySummary(lm.log, contentType, r.ContentLength, r.Method, bs)
		}
	}

	/* Next */

	lm.next.ServeHTTP(w, r)
}

var opts struct {
	ListenAddr       string `short:"a" long:"addr" description:"Listen address eg 127.0.0.1:8080" default:":8080"`
	TlsAlgo          string `short:"k" long:"tls" choice:"off" choice:"rsa" choice:"ecdsa" choice:"ed25519" default:"off" optional:"yes" optional-value:"rsa" description:"Generate and present a self-signed TLS certificate? No flag / -k=off: plaintext. -k: TLS with RSA certs. -k=foo TLS with $foo certs"`
	NegotiationFull  bool   `short:"N" long:"negotiation" description:"Print transport (eg TLS) setup negotiation values, ie what both sides offer to support"`
	TransportSummary bool   `short:"t" long:"transport" description:"Print important agreed transport (eg TLS) parameters"`
	TransportFull    bool   `short:"T" long:"transport-full" description:"Print all agreed transport (eg TLS) parameters"`
	HeadSummary      bool   `short:"m" long:"head" description:"Print important header values"`
	HeadFull         bool   `short:"M" long:"head-full" description:"Print entire request head"`
	BodySummary      bool   `short:"b" long:"body" description:"Print truncated body"`
	BodyFull         bool   `short:"B" long:"body-full" description:"Print full body"`
	Output           string `short:"o" long:"output" description:"Log output format" choice:"auto" choice:"pretty" choice:"json" default:"auto"`
	Response         string `short:"r" long:"response" description:"HTTP response body format" choice:"none" choice:"text" choice:"json" choice:"json-aws-api" choice:"xml" default:"text"`
	Status           int    `short:"s" long:"status" description:"Http status code to return" default:"200"`
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
		op = output.NewTty(false) // no color
	case "pretty":
		op = output.NewTty(true) // color
	case "json":
		op = output.Log{}
	case "auto":
		if isatty.IsTerminal(os.Stdout.Fd()) {
			op = output.NewTty(true)
		} else {
			op = output.Log{}
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
		w.Write(bytes)
	}

	mux := &http.ServeMux{}
	mux.HandleFunc("/", handler)
	loggingMux := &logMiddle{
		log:    log,
		next:   mux,
		output: op,
	}

	if opts.TlsAlgo != "off" {
		loggingMux.caPair, err = loggingMux.genSelfSignedCa()
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
				log.Info("HTTP server listening", "Addr", l.Addr(), "transport", "tls", "algo", opts.TlsAlgo)
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

	if opts.TlsAlgo != "off" {
		srv.TLSConfig = &tls.Config{
			/* Hooks in order they're called */
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				log.V(1).Info("TLS ClientHello received")

				if opts.NegotiationFull {
					op.TLSNegFull(log, hi)
				}

				// TODO proper op Method
				if opts.TransportFull {
					fmt.Println("ServerName:", hi.ServerName)
				} else if opts.TransportSummary {
					fmt.Println("ServerName:", hi.ServerName)
				}

				return nil, nil // option to bail handshake or change TLSConfig
			},
			GetCertificate: loggingMux.genServingCert,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				log.V(1).Info("TLS built-in cert verification finished")
				return nil // can do extra cert verification and reject
			},
			VerifyConnection: func(cs tls.ConnectionState) error {
				log.V(1).Info("TLS: all cert verification finished")

				if opts.TransportFull {
					op.TransportFull(log, &cs)
				} else if opts.TransportSummary {
					// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
					op.TransportSummary(log, &cs)
				}

				return nil // can inspect all connection and TLS info and reject
			},
		}
		log.Error(srv.ListenAndServeTLS("", ""), "Shutting down")
	} else {
		log.Error(srv.ListenAndServe(), "Shutting down")
	}
}

var (
	certCacheLock sync.Mutex
	certCache     map[string]*tls.Certificate
)

func init() {
	certCache = make(map[string]*tls.Certificate)
}

func (lm *logMiddle) genCertPair(settings *x509.Certificate, parent *tls.Certificate) (*tls.Certificate, error) {

	if len(settings.DNSNames) > 1 {
		panic(errors.New("only support one SAN atm"))
	}

	name := settings.DNSNames[0]
	log := lm.log.WithValues("name", name)

	certCacheLock.Lock()
	if cert, ok := certCache[name]; ok {
		log.V(1).Info("Returning from cert cache")
		certCacheLock.Unlock()
		return cert, nil
	}
	certCacheLock.Unlock()

	lm.certSerial++
	settings.SerialNumber = big.NewInt(lm.certSerial)
	log = log.WithValues("serial", lm.certSerial)

	var signerSettings *x509.Certificate
	var signerKey crypto.PrivateKey
	if parent != nil {
		signerSettings, _ = x509.ParseCertificate(parent.Certificate[0]) // annoyingly the call to x509.CreateCertificate() gives us []byte, not a typed object, so that's what ends up in the tls.Certificate we have in hand here. That does have a typed .Leaf, but it's lazy-generated
		signerKey = parent.PrivateKey
	}

	keyPem := new(bytes.Buffer)
	var certBytes []byte

	switch opts.TlsAlgo {
	case "rsa":
		log.V(1).Info("Generating keypair and x509 cert for it", "key", "rsa:4096")

		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}

		pem.Encode(keyPem, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})

		// Self-signing?
		if parent == nil {
			signerKey = key
			signerSettings = settings
		}

		certBytes, err = x509.CreateCertificate(rand.Reader, settings, signerSettings, &key.PublicKey, signerKey)
		if err != nil {
			return nil, err
		}

	case "ecdsa":
		log.V(1).Info("Generating keypair and x509 cert for it", "key", "ecdsa:p256")

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		keyBytes, _ := x509.MarshalECPrivateKey(key)
		pem.Encode(keyPem, &pem.Block{
			Type:  "ECDSA PRIVATE KEY",
			Bytes: keyBytes,
		})

		// Self-signing?
		if parent == nil {
			signerKey = key
			signerSettings = settings
		}

		certBytes, err = x509.CreateCertificate(rand.Reader, settings, signerSettings, &key.PublicKey, signerKey)
		if err != nil {
			return nil, err
		}

	case "ed25519":
		log.V(1).Info("Generating keypair and x509 cert for it", "key", "ed25519")

		pubKey, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
		pem.Encode(keyPem, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})

		// Self-signing?
		if parent == nil {
			signerKey = key
			signerSettings = settings
		}

		certBytes, err = x509.CreateCertificate(rand.Reader, settings, signerSettings, pubKey, signerKey)
		if err != nil {
			return nil, err
		}

	default:
		panic(errors.New("bottom"))
	}

	certPem := new(bytes.Buffer)
	pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	pair, err := tls.X509KeyPair(certPem.Bytes(), keyPem.Bytes())

	// append parent and its ancestory chain
	if parent != nil {
		pair.Certificate = append(pair.Certificate, parent.Certificate...)
	}

	certCacheLock.Lock()
	certCache[name] = &pair
	certCacheLock.Unlock()

	return &pair, err
}

func (lm *logMiddle) genSelfSignedCa() (*tls.Certificate, error) {

	caSettings := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "http-log self-signed ca",
		},
		DNSNames:              []string{"ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return lm.genCertPair(caSettings, nil)
}

func (lm *logMiddle) genServingCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {

	lm.log.V(1).Info("TLS: get serving cert callback")

	dnsName := "localhost"
	if helloInfo.ServerName != "" {
		dnsName = helloInfo.ServerName
	}

	servingSettings := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "http-log",
		},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	return lm.genCertPair(servingSettings, lm.caPair)
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
