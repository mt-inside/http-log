package codec

import "encoding/json"

// AwsAPIGwRequest is the envelope struct for requests from AWS API Gateway
type AwsAPIGwRequest map[string]interface{}

// AwsAPIGwResponse is the envelope struct for responses to AWS API Gateway
type AwsAPIGwResponse struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Base64     bool              `json:"isBase64Encoded"`
	Body       string            `json:"body"`
}

// AwsAPIGwWrap wraps a response map and status code in the AWS API Gateway response envelope
func AwsAPIGwWrap(respCode int, body interface{}) AwsAPIGwResponse {
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}

	return AwsAPIGwResponse{
		respCode,
		map[string]string{},
		false,
		string(bodyJSON),
	}
}
