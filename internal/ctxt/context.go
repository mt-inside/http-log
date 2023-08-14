package ctxt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/mt-inside/http-log/pkg/state"
)

type tCtxKey string

var reqDataKey = tCtxKey("reqData")
var respDataKey = tCtxKey("respData")
var ctxCancelKey = tCtxKey("ctxCancel")

func fromHTTPRequest(r *http.Request, key tCtxKey) any {
	ctx := r.Context()

	val := ctx.Value(key)
	if val == nil {
		panic(fmt.Errorf("can't find key %s in context", key))
	}
	return val
}

func ReqDataToContext(ctx context.Context, d *state.RequestData) context.Context {
	return context.WithValue(ctx, reqDataKey, d)
}
func RespDataToContext(ctx context.Context, d *state.ResponseData) context.Context {
	return context.WithValue(ctx, respDataKey, d)
}
func CtxCancelToContext(ctx context.Context, cancel context.CancelFunc) context.Context {
	return context.WithValue(ctx, ctxCancelKey, cancel)
}
func ReqDataFromHTTPRequest(r *http.Request) *state.RequestData {
	return fromHTTPRequest(r, reqDataKey).(*state.RequestData)
}
func RespDataFromHTTPRequest(r *http.Request) *state.ResponseData {
	return fromHTTPRequest(r, respDataKey).(*state.ResponseData)
}
func CtxCancelFromHTTPRequest(r *http.Request) context.CancelFunc {
	return fromHTTPRequest(r, ctxCancelKey).(context.CancelFunc)
}
