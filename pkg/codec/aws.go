package codec

import "encoding/json"

type AwsApiGwRequest map[string]interface{}

type AwsApiGwResponse struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Base64     bool              `json:"isBase64Encoded"`
	Body       string            `json:"body"`
}

func AwsApiGwWrap(body interface{}) AwsApiGwResponse {
	bodyJson, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}

	return AwsApiGwResponse{
		200,
		map[string]string{},
		false,
		string(bodyJson),
	}
}
