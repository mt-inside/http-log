package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/mt-inside/go-usvc"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

func HandleRequest(
	ctx context.Context,
	input map[string]interface{},
) (
	codec.AwsApiGwResponse,
	error,
) {
	log := usvc.GetLogger(false)
	op := output.NewTty(false)

	requestContext := input["requestContext"].(map[string]interface{})

	// input.headers is nil if there were no headers, like a test invoccation
	// - NB: not the empty map, not a non-existant key
	var headers map[string]interface{}
	if input["headers"] == nil {
		headers = map[string]interface{}{"User-Agent": "<none>"}
	} else {
		headers = input["headers"].(map[string]interface{})
	}

	/* Headers */

	op.HeadSummary(
		log,
		requestContext["protocol"].(string),
		requestContext["httpMethod"].(string),
		input["path"].(string),
		getHeader(headers, "User-Agent"),
	)

	/* Body */

	var body, contentType string
	if input["body"] == nil {
		body = ""
		contentType = "<n/a>"
	} else {
		body = input["body"].(string)
		contentType = getHeader(headers, "content-type")
	}

	op.BodySummary(log, contentType, int64(len(body)), body)

	/* Reply */

	// lc, _ := lambdacontext.FromContext(ctx)
	// res := map[string]string{
	// 	"context": spew.Sdump(lc),
	// 	"input":   spew.Sdump(input),
	// }
	res := map[string]string{"logged": "ok", "by": "http-log"}

	return codec.AwsApiGwWrap(res), nil
}

func main() {
	lambda.Start(HandleRequest)
}

func getHeader(headers map[string]interface{}, key string) string {
	if headers[key] == nil {
		return "<no " + key + ">"
	}
	return headers[key].(string) // TODO case insenstive match, cause it looks client-dependant
}
