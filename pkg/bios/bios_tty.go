package bios

import (
	"fmt"
	"os"

	"github.com/mt-inside/http-log/pkg/build"
	"github.com/mt-inside/http-log/pkg/output"
)

type TtyBios struct {
	s output.TtyStyler
}

func NewTtyBios(s output.TtyStyler) TtyBios {
	return TtyBios{s}
}

func (b TtyBios) Version() {
	fmt.Printf(
		"%s\n",
		// TODO: build time
		b.s.Noun(build.NameAndVersion()),
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
