package state

import (
	"net"
	"net/url"
	"time"
)

type ResponseData struct {
	ProxyRequestTime         time.Time
	PassthroughURL           *url.URL
	PassthroughLocalAddress  net.Addr
	PassthroughRemoteAddress net.Addr

	HttpHeaderTime time.Time
	HttpStatusCode int

	HttpBodyTime      time.Time // When the body finished being read
	HttpContentLength int64
	HttpContentType   string
	HttpBody          []byte
	HttpBodyLen       int64
}

func NewResponseData() *ResponseData {
	return &ResponseData{}
}
