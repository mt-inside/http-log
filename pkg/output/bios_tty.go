package output

import (
	"fmt"
	"os"

	"github.com/go-logr/logr"

	"github.com/mt-inside/go-usvc"
)

type TtyBios struct {
	s   TtyStyler
	log logr.Logger
}

func NewTtyBios(s TtyStyler, verbosity int) TtyBios {
	// TODO: take verbosity level arg, use here
	return TtyBios{s, usvc.GetLogger(false, verbosity).V(1)}
}

// Using a logger is a nice way to get nice output for now. In future it could pretty print
func (b TtyBios) Trace(msg string, keysAndValues ...interface{}) {
	b.log.Info(msg, keysAndValues...)
}
func (b TtyBios) TraceWithName(name, msg string, keysAndValues ...interface{}) {
	b.log.WithName(name).Info(msg, keysAndValues...)
}

// TODO to stderr. Also anti-pattern surely?
func (b TtyBios) GetLogger() logr.Logger {
	return b.log
}

func (b TtyBios) PrintOk(msg string) {
	fmt.Println(b.s.RenderOk(msg))
}
func (b TtyBios) PrintInfo(msg string) {
	fmt.Println(b.s.RenderInfo(msg))
}
func (b TtyBios) PrintWarn(msg string) {
	fmt.Println(b.s.RenderWarn(msg))
}
func (b TtyBios) PrintErr(msg string) {
	fmt.Println(b.s.RenderErr(msg))
}

func (b TtyBios) CheckPrintInfo(err error) bool {
	if err != nil {
		b.PrintInfo(err.Error())
		return true
	}
	return false
}
func (b TtyBios) CheckPrintWarn(err error) bool {
	if err != nil {
		b.PrintWarn(err.Error())
		return true
	}
	return false
}
func (b TtyBios) CheckPrintErr(err error) bool {
	if err != nil {
		b.PrintErr(err.Error())
		return true
	}
	return false
}

func (b TtyBios) Unwrap(err error) {
	if err != nil {
		b.PrintErr(err.Error())
		//panic(errors.New("backtrace"))
		os.Exit(1)
	}
}
