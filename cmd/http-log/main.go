package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
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
* print all possible in the http.Server and tls.Config callbacks - just L7 stuff in the http handler
* combine code with lb-checker - stuff to render certs, tls.connectionstate, etc
* if present, print
*   credentials
*   fragment
*   query (one line in summary, spell out k/v in full)
 */

// TODO!!
var tmpCa *tls.Certificate

type outputter interface {
	TransportSummary(log logr.Logger, cs *tls.ConnectionState)
	TransportFull(log logr.Logger, cs *tls.ConnectionState)
	HeadSummary(log logr.Logger, proto, method, path, host, ua string, respCode int)
	HeadFull(log logr.Logger, r *http.Request, respCode int)
	BodySummary(log logr.Logger, contentType string, contentLength int64, body string)
	BodyFull(log logr.Logger, contentType string, r *http.Request, body string)
}

var requestNo uint

func logMiddle(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)

		// TODO move logging in here
	}
	return http.HandlerFunc(fn)
}

var opts struct {
	ListenAddr       string `short:"a" long:"addr" description:"Listen address eg 127.0.0.1:8080" default:":8080"`
	TlsAlgo          string `short:"k" long:"tls" choice:"off" choice:"rsa" choice:"ecdsa" default:"off" optional:"yes" optional-value:"rsa" description:"Generate and present a self-signed TLS certificate? No flag / -k=off: plaintext. -k: TLS with RSA certs. -k=foo TLS with $foo certs"`
	TransportSummary bool   `short:"t" long:"transport" description:"Print important transport (eg TLS) parameters"`
	TransportFull    bool   `short:"T" long:"transport-full" description:"Print all transport (eg TLS) parameters"`
	HeadSummary      bool   `short:"m" long:"head" description:"Print important header values"`
	HeadFull         bool   `short:"M" long:"head-full" description:"Print entire request head"`
	BodySummary      bool   `short:"b" long:"body" description:"Print truncated body"`
	BodyFull         bool   `short:"B" long:"body-full" description:"Print full body"`
	Output           string `short:"o" long:"output" description:"Output format" choice:"none" choice:"text" choice:"json" choice:"json-aws-api" choice:"xml" default:"text"`
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

	log.Info("TLS", "on", opts.TlsAlgo != "off", "algo", opts.TlsAlgo)

	var op outputter
	if isatty.IsTerminal(os.Stdout.Fd()) {
		op = output.NewTty(true)
	} else {
		op = output.Log{}
	}

	/*
		TODO
		* make this do dynamic certs based on a given / self-gen'd root key - will need to intercept the transport layer socket accept?
		* make a client that prints (in color) http server details - canonical DNS name, ip, cert details inc sans, server header, ALPN details
	*/

	// TODO make a struct with this method on, and op, opts in its fields
	handler := func(w http.ResponseWriter, r *http.Request) {
		log := log.WithValues("Request", requestNo)
		requestNo++ // Think everything is single-threaded...

		/* Transport */

		if r.TLS != nil {
			if opts.TransportFull {
				op.TransportFull(log, r.TLS)
			} else if opts.TransportSummary {
				// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
				op.TransportSummary(log, r.TLS)
			}
		}

		/* Headers */

		userAgent, _ := getHeader(r, "User-Agent")
		if opts.HeadFull {
			op.HeadFull(log, r, opts.Status)
		} else if opts.HeadSummary {
			// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
			op.HeadSummary(log, r.Proto, r.Method, r.Host, r.URL.String(), userAgent, opts.Status)
		}

		/* Body */

		contentType, _ := getHeader(r, "Content-Type")
		if opts.BodyFull || opts.BodySummary {
			bs, err := io.ReadAll(r.Body)
			if err != nil {
				log.Error(err, "failed to get body")
			}

			if opts.BodyFull {
				op.BodyFull(log, contentType, r, string(bs))
			} else if opts.BodySummary {
				op.BodySummary(log, contentType, r.ContentLength, string(bs))
			}
		}

		/* Reply */

		w.WriteHeader(opts.Status)

		// TODO:
		// - turn into getReply(), used by all these and the lambda
		// - config option to add arbitrary pair to it
		// - config option to en/disable the timestamp
		body := map[string]string{"logged": "ok", "by": "http-log", "at": time.Now().Format(time.RFC3339Nano)}

		var err error
		switch opts.Output {
		case "none":
		case "text":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "Logged by http-log\n")
		case "json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			err = json.NewEncoder(w).Encode(body)
		case "json-aws-api":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			err = json.NewEncoder(w).Encode(codec.AwsApiGwWrap(body))
		case "xml":
			w.Header().Set("Content-Type", "application/xml")
			err = xml.NewEncoder(w).Encode(struct {
				XMLName xml.Name `xml:"status"`
				Logged  string
				By      string
			}{Logged: "ok", By: "http-log"})
		}
		if err != nil {
			panic(err)
		}
	}

	log.Info("http-log v0.5")

	mux := &http.ServeMux{}
	mux.HandleFunc("/", handler)
	loggingMux := logMiddle(mux)

	srv := &http.Server{
		Addr:         opts.ListenAddr,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      loggingMux,
		ConnState:    func(c net.Conn, cs http.ConnState) { fmt.Println("Http server connection state change to", cs) },
		BaseContext: func(l net.Listener) context.Context {
			fmt.Println("Http server listening, TODO print interesting listener info")
			return context.Background()
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			fmt.Println("Http server connection accepted, TODO print interesting conn info")
			return ctx
		},
	}

	log.Info("Listening", "addr", opts.ListenAddr)
	if opts.TlsAlgo != "off" {
		caPair, err := genSelfSignedCa()
		if err != nil {
			panic(err)
		}
		tmpCa = caPair // TODO!
		srv.TLSConfig = &tls.Config{
			GetCertificate: genServingCert,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				fmt.Println("ClientHello received, config change hook")
				return nil, nil
			},
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				fmt.Println("Built-in cert verification finished, extra verification hook")
				return nil
			},
			VerifyConnection: func(tls.ConnectionState) error {
				fmt.Println("All cert verification finished, final connection validation hook")
				return nil
			},
		}
		log.Error(srv.ListenAndServeTLS("", ""), "Shutting down")
	} else {
		log.Error(srv.ListenAndServe(), "Shutting down")
	}
}

func genCertPair(settings *x509.Certificate, parent *tls.Certificate) (*tls.Certificate, error) {

	// TODO: Cache them by ServerName

	var parentSettings *x509.Certificate
	var parentKey crypto.PrivateKey
	if parent != nil {
		parentSettings, _ = x509.ParseCertificate(parent.Certificate[0]) // annoyingly the call to x509.CreateCertificate() gives us []byte, not a typed object, so that's what ends up in the tls.Certificate we have in hand here. That does have a typed .Leaf, but it's lazy-generated
		parentKey = parent.PrivateKey
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
			parentKey = key
			parentSettings = settings
		}

		certBytes, err = x509.CreateCertificate(rand.Reader, settings, parentSettings, &key.PublicKey, parentKey)
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
			parentKey = key
			parentSettings = settings
		}

		certBytes, err = x509.CreateCertificate(rand.Reader, settings, parentSettings, &key.PublicKey, parentKey)
		if err != nil {
			return nil, err
		}

	// TODO: add ed25519

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

func genServingCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {

	fmt.Println("Http get serving cert callback")

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

	return genCertPair(servingSettings, tmpCa)
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
