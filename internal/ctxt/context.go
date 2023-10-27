package ctxt

import (
	"context"
	"fmt"

	"github.com/mt-inside/http-log/pkg/state"
)

type tCtxKey string

var srvDataKey = tCtxKey("srvData")
var reqDataKey = tCtxKey("reqData")
var respDataKey = tCtxKey("respData")

func fromContext(ctx context.Context, key tCtxKey) any {
	val := ctx.Value(key)
	if val == nil {
		panic(fmt.Errorf("can't find key %s in context", key))
	}
	return val
}

func SrvDataToContext(ctx context.Context, d *state.DaemonData) context.Context {
	return context.WithValue(ctx, srvDataKey, d)
}
func ReqDataToContext(ctx context.Context, d *state.RequestData) context.Context {
	return context.WithValue(ctx, reqDataKey, d)
}
func RespDataToContext(ctx context.Context, d *state.ResponseData) context.Context {
	return context.WithValue(ctx, respDataKey, d)
}

func SrvDataFromContext(ctx context.Context) *state.DaemonData {
	return fromContext(ctx, srvDataKey).(*state.DaemonData)
}
func ReqDataFromContext(ctx context.Context) *state.RequestData {
	return fromContext(ctx, reqDataKey).(*state.RequestData)
}
func RespDataFromContext(ctx context.Context) *state.ResponseData {
	return fromContext(ctx, respDataKey).(*state.ResponseData)
}
