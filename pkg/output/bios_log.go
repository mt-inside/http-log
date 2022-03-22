package output

import (
	"errors"
	"os"

	"github.com/go-logr/logr"
)

type LogBios struct {
	l logr.Logger
}

func NewLogBios(l logr.Logger) LogBios {
	return LogBios{l}
}

func (b LogBios) Banner(s string) {
}

func (b LogBios) Trace(msg string, keysAndValues ...interface{}) {
	b.l.V(1).Info(msg, keysAndValues...)
}

// TODO Same mechanism as Trace for now; this should write to stderr
func (b LogBios) GetLogger() logr.Logger {
	return b.l.V(2)
}

func (b LogBios) PrintInfo(msg string) {
	b.l.Info("Info", "msg", msg)
}
func (b LogBios) CheckInfo(err error) bool {
	if err != nil {
		b.PrintInfo(err.Error())
		return false
	}
	return true
}

func (b LogBios) PrintWarn(msg string) {
	b.l.Info("Warning", "msg", msg)
}
func (b LogBios) CheckWarn(err error) bool {
	if err != nil {
		b.PrintWarn(err.Error())
		return false
	}
	return true
}

func (b LogBios) PrintErr(msg string) {
	b.l.Error(errors.New(msg), "Error")
	//panic(err) - for backtraces
	os.Exit(1)
}
func (b LogBios) CheckErr(err error) {
	if err != nil {
		b.l.Error(err, "Error")
		//panic(err) - for backtraces
		os.Exit(1)
	}
}

func (b LogBios) CheckOk(ok bool) {
	if !ok {
		//panic(errors.New("Not OK!"))
		b.l.Info("Not OK!")
		os.Exit(1)
	}
}
