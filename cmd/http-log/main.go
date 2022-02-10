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
	BodySummary(log logr.Logger, contentType string, contentLength int64, body string)
	BodyFull(log logr.Logger, contentType string, r *http.Request, body string)
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
			lm.output.BodyFull(lm.log, contentType, r, string(bs))
		} else if opts.BodySummary {
			lm.output.BodySummary(lm.log, contentType, r.ContentLength, string(bs))
		}
	}

	/* Next */

	lm.next.ServeHTTP(w, r)
}

var opts struct {
	ListenAddr       string `short:"a" long:"addr" description:"Listen address eg 127.0.0.1:8080" default:":8080"`
	TlsAlgo          string `short:"k" long:"tls" choice:"off" choice:"rsa" choice:"ecdsa" choice:"ed25519" default:"off" optional:"yes" optional-value:"rsa" description:"Generate and present a self-signed TLS certificate? No flag / -k=off: plaintext. -k: TLS with RSA certs. -k=foo TLS with $foo certs"`
	TransportSummary bool   `short:"t" long:"transport" description:"Print important transport (eg TLS) parameters"`
	TransportFull    bool   `short:"T" long:"transport-full" description:"Print all transport (eg TLS) parameters"`
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
		w.Write(bytes)
		w.WriteHeader(opts.Status)
	}

	mux := &http.ServeMux{}
	mux.HandleFunc("/", handler)
	loggingMux := &logMiddle{
		log:    log,
		next:   mux,
		output: op,
	}

	if opts.TlsAlgo != "off" {
		loggingMux.caPair, err = genSelfSignedCa()
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
				log.Info("Hook", "Event", "HTTP server listening", "Addr", l.Addr(), "security", "plaintext")
			default: // *tls.listener
				log.Info("Hook", "Event", "HTTP server listening", "Addr", l.Addr(), "security", "tls", "algo", opts.TlsAlgo)
			}
			return context.Background()
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			requestNo++ // Think everything is single-threaded...
			log.Info("Hook", "Event", "L4 connection accepted", "RequestCount", requestNo, "from", c.RemoteAddr())

			return ctx
		},
		ConnState: func(c net.Conn, cs http.ConnState) {
			log.Info("Hook", "Event", "HTTP server connection state change", "State", cs)
		},
	}

	if opts.TlsAlgo != "off" {
		srv.TLSConfig = &tls.Config{
			GetCertificate: loggingMux.genServingCert,
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				log.Info("Hook", "Event", "TLS ClientHello received")

				if opts.TransportFull {
					op.TLSNegFull(log, hi)
				}

				return nil, nil // option to bail handshake or change TLSConfig
			},
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				log.Info("Hook", "Event", "TLS built-in cert verification finished")
				return nil // can do extra cert verification and reject
			},
			VerifyConnection: func(cs tls.ConnectionState) error {
				log.Info("Hook", "Event", "TLS: all cert verification finished")

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

func genCertPair(settings *x509.Certificate, parent *tls.Certificate) (*tls.Certificate, error) {

	// TODO: Cache them by ServerName

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

	return &pair, err
}

func genSelfSignedCa() (*tls.Certificate, error) {

	caSettings := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: "http-log self-signed ca",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return genCertPair(caSettings, nil)
}

func (lm *logMiddle) genServingCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {

	lm.log.Info("Hook", "Event", "TLS: get serving cert callback")

	dnsName := "localhost"
	if helloInfo.ServerName != "" {
		dnsName = helloInfo.ServerName
	}

	servingSettings := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
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

	return genCertPair(servingSettings, lm.caPair)
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
