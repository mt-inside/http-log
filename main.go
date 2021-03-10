package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/jessevdk/go-flags"
	. "github.com/logrusorgru/aurora"
	"github.com/mattn/go-isatty"
	"github.com/mt-inside/go-usvc"
)

/* TODO:
* if present, print
*   credentials
*   fragment
*   query (one line in summary, spell out k/v in full)
 */

type output interface {
	headSummary(log logr.Logger, r *http.Request)
	headFull(log logr.Logger, r *http.Request)
	bodySummary(log logr.Logger, r *http.Request, body []byte)
	bodyFull(log logr.Logger, r *http.Request, body []byte)
}

type outputTty struct{}
type outputLog struct{}

var requestNo uint

func main() {
	log := usvc.GetLogger(false)

	var opts struct {
		ListenAddr  string `short:"a" long:"addr" description:"Listen address eg 127.0.0.1:8080" default:":8080"`
		HeadSummary bool   `short:"m" long:"head" description:"Print important header values"`
		HeadFull    bool   `short:"M" long:"head-fulll" description:"Print entire request head"`
		BodySummary bool   `short:"b" long:"body" description:"Print truncated body"`
		BodyFull    bool   `short:"B" long:"body-full" description:"Print full body"`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}
	if !opts.HeadSummary && !opts.HeadFull && !opts.BodySummary && !opts.BodyFull {
		opts.HeadSummary = true
	}

	var op output
	if isatty.IsTerminal(os.Stdout.Fd()) {
		op = outputTty{}
	} else {
		op = outputLog{}
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log := log.WithValues("Request", requestNo)
		requestNo++ // Think everything is single-threaded...

		/* Headers */

		if opts.HeadFull {
			op.headFull(log, r)
		} else if opts.HeadSummary {
			op.headSummary(log, r)
		}

		/* Body */

		if opts.BodyFull || opts.BodySummary {
			bs, err := io.ReadAll(r.Body)
			if err != nil {
				log.Error(err, "failed to get body")
			}

			if opts.BodyFull {
				op.bodyFull(log, r, bs)
			} else if opts.BodySummary {
				op.bodySummary(log, r, bs)
			}
		}

		/* Reply */

		fmt.Fprintf(w, "Logged by http-log\n")
	})

	log.Info("http-log v0.5")
	log.Info("Listening", "addr", opts.ListenAddr)
	log.Error(http.ListenAndServe(opts.ListenAddr, nil), "Shutting down")
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

func (o outputTty) headFull(log logr.Logger, r *http.Request) {
	fmt.Printf("%s %s %s%s\n", Blue(r.Proto), Green(r.Method), Cyan(r.Host), Cyan(r.RequestURI))
	for k, v := range r.Header {
		fmt.Printf("%s = %v\n", k, strings.Join(v, ","))
	}
}
func (o outputTty) headSummary(log logr.Logger, r *http.Request) {
	userAgent, _ := getHeader(r, "User-Agent")

	fmt.Printf("%s %s %s%s by %s\n", Blue(r.Proto), Green(r.Method), Cyan(r.Host), Cyan(r.RequestURI), Cyan(userAgent))
}
func (o outputTty) bodyFull(log logr.Logger, r *http.Request, bs []byte) {
	contentType, _ := getHeader(r, "Content-Type")
	fmt.Printf("%s %d bytes of %s \n", Red("=>"), Cyan(r.ContentLength), Cyan(contentType))
	fmt.Printf("%v", string(bs)) // assumes utf8
	fmt.Println()
}
func (o outputTty) bodySummary(log logr.Logger, r *http.Request, bs []byte) {
	contentType, _ := getHeader(r, "Content-Type")

	bodyLen := len(bs)
	printLen := min(bodyLen, 72)

	fmt.Printf("%s %d bytes of %s \n", Red("=>"), Cyan(r.ContentLength), Cyan(contentType))
	fmt.Printf("%v", string(bs[0:printLen])) // assumes utf8
	if bodyLen > printLen {
		fmt.Printf("<%d bytes elided>", len(bs)-printLen)
	}
	fmt.Println()
}

func (o outputLog) headFull(log logr.Logger, r *http.Request) {
	log.Info("Header", "Name", "proto", "Values", r.Proto)
	log.Info("Header", "Name", "method", "Values", r.Method)
	log.Info("Header", "Name", "host", "Values", r.Host)
	log.Info("Header", "Name", "path", "Values", r.RequestURI)
	for k, v := range r.Header {
		log.Info("Header", "Name", k, "Values", v)
	}
}
func (o outputLog) headSummary(log logr.Logger, r *http.Request) {
	userAgent, _ := getHeader(r, "User-Agent")

	log.Info(
		"Headers summary",
		"proto", r.Proto,
		"method", r.Method,
		"host", r.Host,
		"path", r.RequestURI,
		"user-agent", userAgent,
	)
}
func (o outputLog) bodyFull(log logr.Logger, r *http.Request, bs []byte) {
	contentType, _ := getHeader(r, "Content-Type")
	log.Info("Body",
		"len", r.ContentLength,
		"type", contentType,
		"content", bs,
	)
}
func (o outputLog) bodySummary(log logr.Logger, r *http.Request, bs []byte) {
	contentType, _ := getHeader(r, "Content-Type")

	bodyLen := len(bs)
	printLen := min(bodyLen, 72)

	log.Info("Body Summary",
		"len", r.ContentLength,
		"type", contentType,
		"content", string(bs[0:printLen]),
		"elided", bodyLen-printLen,
	)
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
