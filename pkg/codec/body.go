package codec

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"
)

// TODO:
// - turn into getReply(), used by all these and the lambda
// - config option to add arbitrary pair to it
// - config option to en/disable the timestamp

func GetBody() map[string]string {
	return map[string]string{
		"logged": "ok",
		"by":     "http-log",
		"at":     time.Now().Format(time.RFC3339Nano),
	}
}

func BytesAndMime(respCode int, body map[string]string, typ string) (bytes []byte, mime string) {

	var err error

	switch typ {
	case "none":
	case "text":
		bytes = []byte(fmt.Sprintf("%v\n", body))
		mime = "text/plain; charset=utf-8"
	case "json":
		bytes, err = json.Marshal(body)
		mime = "application/json; charset=utf-8"
	case "json-aws-api":
		bytes, err = json.Marshal(AwsApiGwWrap(respCode, body))
		mime = "application/json; charset=utf-8"
	case "xml":
		bytes, err = xml.Marshal(
			// TODO: build this by reflection
			struct {
				XMLName xml.Name `xml:"status"`
				Logged  string
				By      string
			}{Logged: "ok", By: "http-log"},
		)
		mime = "application/xml"
	}

	if err != nil {
		panic(err)
	}

	return
}
