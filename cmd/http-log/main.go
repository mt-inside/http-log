package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
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
	HeadSummary(log logr.Logger, proto, method, path, host, ua string)
	HeadFull(log logr.Logger, r *http.Request)
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

func main() {

	log := usvc.GetLogger(false)

	var opts struct {
		ListenAddr       string `short:"a" long:"addr" description:"Listen address eg 127.0.0.1:8080" default:":8080"`
		Tls              bool   `short:"k" long:"tls" description:"Generate a self-signed TLS certificate and present it"`
		TransportSummary bool   `short:"t" long:"transport" description:"Print important transport (eg TLS) parameters"`
		TransportFull    bool   `short:"T" long:"transport-full" description:"Print all transport (eg TLS) parameters"`
		HeadSummary      bool   `short:"m" long:"head" description:"Print important header values"`
		HeadFull         bool   `short:"M" long:"head-full" description:"Print entire request head"`
		BodySummary      bool   `short:"b" long:"body" description:"Print truncated body"`
		BodyFull         bool   `short:"B" long:"body-full" description:"Print full body"`
		Output           string `short:"o" long:"output" description:"Output format" choice:"none" choice:"text" choice:"json" choice:"json-aws-api" choice:"xml" default:"text"`
		Status           int    `short:"s" long:"status" description:"Http status code to return" default:"200"`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}
	if !opts.TransportSummary && !opts.TransportFull && !opts.HeadSummary && !opts.HeadFull && !opts.BodySummary && !opts.BodyFull {
		opts.HeadSummary = true
	}

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
			op.HeadFull(log, r)
		} else if opts.HeadSummary {
			// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
			op.HeadSummary(log, r.Proto, r.Method, r.Host, r.URL.String(), userAgent)
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
	}

	log.Info("Listening", "addr", opts.ListenAddr)
	if opts.Tls {
		caPair, err := genSelfSignedCa()
		if err != nil {
			panic(err)
		}
		tmpCa = caPair // TODO!
		srv.TLSConfig = &tls.Config{
			GetCertificate: genServingCert,
		}
		log.Error(srv.ListenAndServeTLS("", ""), "Shutting down")
	} else {
		log.Error(srv.ListenAndServe(), "Shutting down")
	}
}

func genSelfSignedCa() (*tls.Certificate, error) {

	caSettings := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: "http-log self-signed ca",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// TODO: change to ECDSA. Not least it's orders of mangnitues faster.
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caSettings, caSettings, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	caKeyPem := new(bytes.Buffer)
	pem.Encode(caKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})

	caCertPem := new(bytes.Buffer)
	pem.Encode(caCertPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	})

	caPair, err := tls.X509KeyPair(caCertPem.Bytes(), caKeyPem.Bytes())
	if err != nil {
		return nil, err
	}

	return &caPair, nil
}

func genServingCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {

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

	servingKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	caCert, _ := x509.ParseCertificate(tmpCa.Certificate[0]) // annoyingly the call to x509.CreateCertificate() gives us []byte, not a typed object, so that's what ends up in the tls.Certificate we have in hand here. That does have a typed .Leaf, but it's lazy-generated
	servingCertBytes, err := x509.CreateCertificate(rand.Reader, servingSettings, caCert, &servingKey.PublicKey, tmpCa.PrivateKey)
	if err != nil {
		return nil, err
	}

	servingKeyPem := new(bytes.Buffer)
	pem.Encode(servingKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(servingKey),
	})

	servingCertPem := new(bytes.Buffer)
	pem.Encode(servingCertPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: servingCertBytes,
	})

	certPair, err := tls.X509KeyPair(servingCertPem.Bytes(), servingKeyPem.Bytes())
	if err != nil {
		return nil, err
	}

	return &certPair, nil
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
