package codec

import (
	"net/http"
	"strings"
)

func HeaderRepeatedOrCommaSeparated(headers http.Header, key string) []string {
	hs := headers[http.CanonicalHeaderKey(key)]
	if len(hs) == 1 {
		hs = strings.Split(hs[0], ",") // works fine if string doesn't contain ','
	}
	for i := range hs {
		hs[i] = strings.TrimSpace(hs[i])
	}
	return hs
}

func HeaderFromMap(headers map[string]interface{}, key string) (value string) {
	value = ""
	if h, ok := headers[http.CanonicalHeaderKey(key)]; ok { // TODO we canonicalise the header key, but I don't think they're canonicalised in this map
		value = h.(string)
	}
	return
}
