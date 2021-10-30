package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

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

var requestNo uint

func main() {
	log := usvc.GetLogger(false)

	var opts struct {
		ListenAddr  string `short:"a" long:"addr" description:"Listen address eg 127.0.0.1:8080" default:":8080"`
		HeadSummary bool   `short:"m" long:"head" description:"Print important header values"`
		HeadFull    bool   `short:"M" long:"head-full" description:"Print entire request head"`
		BodySummary bool   `short:"b" long:"body" description:"Print truncated body"`
		BodyFull    bool   `short:"B" long:"body-full" description:"Print full body"`
		Output      string `short:"o" long:"output" description:"output format" choice:"none" choice:"text" choice:"json" choice:"json-aws-api" choice:"xml" default:"text"`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}
	if !opts.HeadSummary && !opts.HeadFull && !opts.BodySummary && !opts.BodyFull {
		opts.HeadSummary = true
	}

	var op output.Output
	if isatty.IsTerminal(os.Stdout.Fd()) {
		op = output.NewTty(true)
	} else {
		op = output.Log{}
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log := log.WithValues("Request", requestNo)
		requestNo++ // Think everything is single-threaded...

		/* Headers */

		userAgent, _ := getHeader(r, "User-Agent")
		if opts.HeadFull {
			op.HeadFull(log, r)
		} else if opts.HeadSummary {
			// unless the request is in the weird proxy form or whatever, URL will only contain a path; scheme, host etc will be empty
			op.HeadSummary(log, r.Proto, r.Method, r.URL.String(), userAgent)
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
