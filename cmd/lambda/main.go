package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/davecgh/go-spew/spew"
	"github.com/mt-inside/go-usvc"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

// TODO: this is SO different, I'm not lambda can share it. Make its own (iface + pair of impls). Can still use bios and styler (for printing+logging certs etc)
type renderer interface {
	Connection(requestNo uint, c net.Conn)
	TLSNegSummary(cs *tls.ClientHelloInfo)
	TLSNegFull(cs *tls.ClientHelloInfo)
	TLSSummary(cs *tls.ConnectionState, clientCa *x509.Certificate)
	TLSFull(cs *tls.ConnectionState, clientCa *x509.Certificate)
	HeadSummary(proto, method, host, ua string, url *url.URL, respCode int)
	HeadFull(r *http.Request, respCode int)
	JWTSummary(tokenErr error, start, end *time.Time, ID, subject, issuer string, audience []string)
	JWTFull(tokenErr error, start, end *time.Time, ID, subject, issuer string, audience []string, sigAlgo, hashAlgo string)
	BodySummary(contentType string, contentLength int64, body []byte)
	BodyFull(contentType string, contentLength int64, body []byte)
}

const (
	respCode = 200 // TODO config
)

func main() {
	lambda.Start(handleRequest)

}

func handleRequest(
	ctx context.Context,
	input map[string]interface{},
) (
	body interface{},
	err error, // TODO what happens if we set this?
) {
	//return handleDump(ctx, input)
	// TODO on the Renderers
	fmt.Printf("%s %s running under %s in %s\n", os.Getenv("AWS_LAMBDA_FUNCTION_NAME"), os.Getenv("AWS_LAMBDA_FUNCTION_VERSION"), os.Getenv("AWS_EXECUTION_ENV"), os.Getenv("AWS_REGION"))

	lc, _ := lambdacontext.FromContext(ctx)

	log := usvc.GetLogger(false, 0) // TODO: verbostiy option
	op := output.NewLogRenderer(log)

	// TODO: finally build that unified config system using viper, cobra, etc. Put it in usvc, have the function take a goflags opts struct? And return a viper?
	// TODO: auto-detect based on type reflection, headers present etc
	envelope := os.Getenv("HTTP_LOG_ENVELOPE")
	switch envelope {
	case "dump":
		return dump(ctx, input)
	case "none":
		return logRaw(op, lc, input)
	case "apigw":
		return logAPIGw(op, lc, input)
	case "alb":
		panic(errors.New("TODO"))
	default:
		panic(errors.New("Unrecognised envelope type"))
	}
}

// Dump mode. Can only be called by invoke api, as it doesn't reply with the envelope for eg api-gw
func dump(
	ctx context.Context,
	input map[string]interface{},
) (
	body interface{},
	err error,
) {
	spew.Dump(ctx)
	spew.Dump(input)

	return codec.GetBody(), nil
}

func logRaw(
	op renderer,
	ctx *lambdacontext.LambdaContext,
	input map[string]interface{},
) (
	interface{},
	error,
) {

	reqTarget := &url.URL{
		Host: ctx.InvokedFunctionArn,
	}

	op.HeadSummary(
		"n/a",
		"n/a",
		"n/a",
		ctx.ClientContext.Client.AppTitle+" "+ctx.ClientContext.Client.AppVersionCode,
		reqTarget,
		respCode,
	)

	body := spew.Sdump(input)

	op.BodyFull(
		"text/plain",
		int64(len(body)),
		[]byte(body),
	)

	return codec.GetBody(), nil
}

func logAPIGw(
	op renderer,
	lc *lambdacontext.LambdaContext,
	input codec.AwsAPIGwRequest,
) (
	interface{},
	error,
) {
	/* wot u see: TODO make MD table
	* direct - context looks ok, input empty map
	* api-gw test - input[headers] is nil (not non-existant, not empty map)
	* - only if no headers supplied - can give a lot of params in the test console, this documents the minimum
	* api-gw real client
	 */

	path := input["path"].(string)

	requestContext := input["requestContext"].(map[string]interface{})
	protocol := requestContext["protocol"].(string)
	method := requestContext["httpMethod"].(string)

	/* api-gw indicates that no headers were supplied with an existant key which maps to null.
	* This is awful, so we replace that with a sentinel object */
	var headers map[string]interface{}
	if input["headers"] != nil {
		headers = input["headers"].(map[string]interface{})
	} else {
		headers = map[string]interface{}{}
	}
	/* There's also mutliValueHeaders, but their "last" values are all present in headers */

	/* Call from API-GW by a real client (not a web console test invocation) */
	userAgent := codec.HeaderFromMap(headers, "User-Agent")
	host := codec.HeaderFromMap(headers, "Host") // There's also requestContext[domainName] but I assume it's only set for custom domains

	var contentType string
	var body []byte
	/* Call with a body */
	if input["body"] != nil {
		contentType = codec.HeaderFromMap(headers, "content-type")
		body = []byte(input["body"].(string)) // It is a string type in the map; take the bytestream of that
	}

	reqTarget := &url.URL{Path: path}

	/* Print cert info */

	if identity, ok := requestContext["identity"].(map[string]interface{}); ok {
		/* Print remote info TODO method on op, called by the accept() hook */

		fmt.Println("Connection from: ", identity["sourceIp"].(string))

		if clientCert, ok := identity["clientCert"].(map[string]interface{}); ok {
			// TODO: move to op func
			fmt.Println(clientCert["subjectDN"].(string))
			fmt.Println(clientCert["issuerDN"].(string))
		}
	}

	/* Print Headers */

	op.HeadSummary(
		protocol,
		method,
		host,
		userAgent,
		reqTarget,
		respCode,
	)

	/* Print Body */

	op.BodySummary(
		contentType,
		int64(len(body)),
		body,
	)

	return codec.AwsAPIGwWrap(respCode, codec.GetBody()), nil
}
