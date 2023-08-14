package codec

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mt-inside/http-log/internal/build"
	"github.com/mt-inside/http-log/pkg/utils"
)

// TODO:
// - turn into getReply(), used by all these and the lambda
// - config option to add arbitrary pair to it
// - config option to en/disable the timestamp

// GetBody generates the standard structured response
func GetBody() map[string]string {
	return map[string]string{
		"logged":  "ok",
		"by":      build.Name,
		"version": build.Version,
		"at":      time.Now().Format(time.RFC3339Nano),
		"host":    utils.Hostname(),
		"ip":      utils.DefaultIP(),
	}
}

// BytesAndMime gives a mimetype and body bytestream for various response types
func BytesAndMime(respCode int, body map[string]string, typ string) (bytes []byte, mime string) {

	var err error

	switch typ {
	case "none":
	case "text":
		var ss []string
		for k, v := range body {
			ss = append(ss, fmt.Sprintf("%s: %s", k, v))
		}
		bytes = []byte(strings.Join(ss, ", ") + "\n")
		mime = "text/plain; charset=utf-8"
	case "json":
		bytes, err = json.Marshal(body)
		mime = "application/json; charset=utf-8"
	case "xml":
		bytes, err = xml.Marshal(
			// TODO: build this by reflection and use all the fields from body
			struct {
				XMLName xml.Name `xml:"status"`
				Logged  string
				By      string
				Version string
			}{Logged: "ok", By: build.Name, Version: build.Version},
		)
		mime = "application/xml"
	default:
		panic(errors.New("unknown body type"))
	}

	if err != nil {
		panic(err)
	}

	return
}
