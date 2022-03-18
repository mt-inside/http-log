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

func NewTtyBios(s TtyStyler) TtyBios {
	return TtyBios{s, usvc.GetLogger(false, 10)}
}

func (b TtyBios) Banner(msg string) {
	fmt.Println()
	fmt.Println(b.s.Bright(fmt.Sprintf("== %s ==", msg)))
	fmt.Println()
}

// Useing a logger is a nice way to get nice output for now. In future it could pretty print
func (b TtyBios) Trace(msg string, keysAndValues ...interface{}) {
	b.log.Info(msg, keysAndValues...)
}

// TODO to stderr
func (b TtyBios) GetLogger() logr.Logger {
	return b.log.V(1)
}

func (b TtyBios) CheckInfo(err error) bool {
	if err != nil {
		fmt.Printf("%s %v\n", b.s.Info("Info"), err)
		return false
	}
	return true
}

func (b TtyBios) CheckWarn(err error) bool {
	if err != nil {
		fmt.Printf("%s %v\n", b.s.Warn("Warning"), err)
		return false
	}
	return true
}

func (b TtyBios) CheckErr(err error) {
	if err != nil {
		//panic(err) - for backtraces
		fmt.Printf("%s %v\n", b.s.Fail("Error"), err)
		os.Exit(1)
	}
}

func (b TtyBios) CheckOk(ok bool) {
	if !ok {
		//panic(errors.New("Not OK!"))
		fmt.Printf("%s Not OK!\n", b.s.Fail("Error"))
		os.Exit(1)
	}
}
