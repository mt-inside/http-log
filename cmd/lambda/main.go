package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/davecgh/go-spew/spew"
	"github.com/mt-inside/go-usvc"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

func HandleRequest(
	ctx context.Context,
	input map[string]interface{}, // TODO typing is hard in golang
) (
	codec.AwsApiGwResponse, // TODO ditto typing
	error, // TODO what happens if we set this?
) {
	//return handleDump(ctx, input)
	return handleLog(ctx, input) // TODO split this into api-gw, alb etc. Take config for which one you're expecting, or ideall auto-detect it
}

func main() {
	lambda.Start(HandleRequest)
}

func getHeader(headers map[string]interface{}, key string) string {
	if val, ok := headers[key]; ok {
		return val.(string) // TODO case insenstive match, cause it looks client-dependant
	} else {
		return "<not set>"
	}
}

// Dump mode. Can only be called by invoke api, as it doesn't reply with the envelope for eg api-gw
//nolint:deadcode,unused
func handleDump(
	ctx context.Context,
	input map[string]interface{},
) (
	map[string]string,
	error,
) {
	lc, _ := lambdacontext.FromContext(ctx)
	res := map[string]string{
		"context": spew.Sdump(lc),
		"input":   spew.Sdump(input),
	}
	return res, nil
}

func handleLog(
	ctx context.Context,
	input map[string]interface{}, // TODO typedef this in codec
) (
	codec.AwsApiGwResponse,
	error, // TODO what happens if we set this?
) {
	log := usvc.GetLogger(false)
	op := output.NewTty(false)

	protocol := "<n/a>"
	method := "<n/a>"
	path := "<n/a>"
	userAgent := "<n/a>"
	contentType := "<n/a>"
	body := ""

	/* wot u see: TODO make MD table
	* direct - context looks ok, input empty map
	* api-gw test - input[headers] is nil (not non-existant, not empty map)
	* - only if no headers supplied - can give a lot of params in the test console, this documents the minimum
	* api-gw real client
	 */

	/* Calls from API-GW */
	if _, ok := input["requestContext"]; ok {
		path = input["path"].(string)

		requestContext := input["requestContext"].(map[string]interface{})
		protocol = requestContext["protocol"].(string)
		method = requestContext["httpMethod"].(string)

		/* api-gw indicates no headers with a present key, which maps to null.
		* This is awful, so we replace that with a sentinel object */
		var headers map[string]interface{}
		if input["headers"] != nil {
			headers = input["headers"].(map[string]interface{})
		} else {
			headers = map[string]interface{}{}
		}

		/* Call from API-GW by a real client (not a web console test invocation) */
		userAgent = getHeader(headers, "User-Agent")

		/* Call with a body */
		if input["body"] != nil {
			contentType = getHeader(headers, "content-type")
			body = input["body"].(string)
		}
	}

	/* Print Headers */

	op.HeadSummary(
		log,
		protocol,
		method,
		path,
		userAgent,
	)

	/* Print Body */

	op.BodySummary(
		log,
		contentType,
		int64(len(body)),
		body,
	)

	/* Reply */

	res := map[string]string{"logged": "ok", "by": "http-log"}

	return codec.AwsApiGwWrap(res), nil // TODO: shouldn't be taken on all paths
}
