package bios

import (
	"fmt"
	"os"
	"runtime"

	"github.com/mt-inside/http-log/internal/build"
	"github.com/mt-inside/http-log/pkg/output"
)

type TtyBios struct {
	s output.TtyStyler
}

func NewTtyBios(s output.TtyStyler) TtyBios {
	return TtyBios{s}
}

func (b TtyBios) Version() {
	h, err := os.Hostname()
	if err != nil {
		h = "<unknown hostname>"
	}
	fmt.Printf(
		"%s %s %s %s %s/%s\n",
		// TODO: build time
		b.s.Noun(build.Name),
		b.s.Number(build.Version),
		b.s.Number(runtime.Version()),
		b.s.Addr(h),
		b.s.Noun(runtime.GOOS),
		b.s.Noun(runtime.GOARCH),
	)
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
