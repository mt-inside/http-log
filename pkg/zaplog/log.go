package zaplog

import (
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/function"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type logger struct {
	telemetry.Logger

	writer logr.Logger
	now    func() time.Time
}

// Logs to stderr
func New() telemetry.Logger {
	lg := &logger{}

	zCfg := zap.NewDevelopmentConfig()
	zCfg.EncoderConfig.EncodeCaller = nil
	zCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	zCfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		// Ignore the time zap gives us and use our own idea of it, which allows us to emit repeatable logs in tests.
		// Note that it's not enough to just subtract a start time from $t, as operations in tests can have different durations.
		enc.AppendString(lg.now().Format("15:04:05"))
	}
	z, err := zCfg.Build()
	if err != nil {
		panic(err)
	}
	zr := zapr.NewLogger(z)

	lg.writer = zr
	lg.now = time.Now
	lg.Logger = function.NewLogger(lg.zaprLog)
	return lg
}

func (l *logger) zaprLog(level telemetry.Level, msg string, err error, values function.Values) {
	args := []any{}
	args = append(args, values.FromContext...)
	args = append(args, values.FromLogger...)
	args = append(args, values.FromMethod...)

	var s string
	sI := -1
	for i := 0; i < len(args); i += 2 {
		if args[i] == "scope" {
			sI = i
			s = args[i+1].(string)
		}
	}
	if sI != -1 {
		args = append(args[:sI], args[sI+2:]...)
	}
	if s == "" {
		s = "<none>"
	}

	switch level {
	case telemetry.LevelError:
		l.writer.WithName(s).Error(err, msg, args...)
	case telemetry.LevelInfo:
		l.writer.WithName(s).Info(msg, args...)
	case telemetry.LevelDebug:
		l.writer.WithName(s).V(1).Info(msg, args...)
	}
}
