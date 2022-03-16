package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/davecgh/go-spew/spew"
	"github.com/mt-inside/go-usvc"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

const (
	respCode   = 200
	expectType = envelopeTypeAPIGw // TODO take from "config"
)

type envelopeType int

const (
	envelopeTypeRaw   envelopeType = iota
	envelopeTypeAPIGw envelopeType = iota
	envelopeTypeALB   envelopeType = iota
)

func main() {
	lambda.Start(handleRequest)
}

func handleRequest(
	ctx context.Context,
	input map[string]interface{},
) (
	interface{},
	error, // TODO what happens if we set this?
) {
	//return handleDump(ctx, input)

	lc, _ := lambdacontext.FromContext(ctx)

	// TODO: auto-detect based on type reflection, headers present etc
	switch expectType {
	case envelopeTypeRaw:
		logRaw(lc, input)
		return codec.GetBody(), nil
	case envelopeTypeAPIGw:
		logAPIGw(lc, input)
		return codec.AwsAPIGwWrap(respCode, codec.GetBody()), nil
	case envelopeTypeALB:
		panic(errors.New("TODO"))
	default:
		panic(errors.New("bottom"))
	}

}

// Dump mode. Can only be called by invoke api, as it doesn't reply with the envelope for eg api-gw
//nolint:deadcode,unused
func handleDump(
	ctx context.Context,
	input map[string]interface{},
) {
	spew.Dump(ctx)
	spew.Dump(input)
}

func logRaw(
	ctx *lambdacontext.LambdaContext,
	input map[string]interface{},
) {
	log := usvc.GetLogger(false)
	op := output.NewTty(log, false) // TODO: log op, fix it up first

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
}

func logAPIGw(
	lc *lambdacontext.LambdaContext,
	input codec.AwsAPIGwRequest,
) {
	log := usvc.GetLogger(false)
	op := output.NewTty(log, false)

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
	userAgent := getHeader(headers, "User-Agent")
	host := getHeader(headers, "Host") // There's also requestContext[domainName] but I assume it's only set for custom domains

	var contentType string
	var body []byte
	/* Call with a body */
	if input["body"] != nil {
		contentType = getHeader(headers, "content-type")
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
}

func getHeader(headers map[string]interface{}, key string) string {
	if val, ok := headers[key]; ok {
		return val.(string) // TODO case insenstive match, cause it looks client-dependant
	}
	return "<not set>"
}
