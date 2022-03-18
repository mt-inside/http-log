package output

import (
	"net/url"
	"strings"

	"github.com/logrusorgru/aurora/v3"
)

type Styler struct {
	au aurora.Aurora

	InfoStyle   aurora.Color
	FailStyle   aurora.Color
	OkStyle     aurora.Color
	WarnStyle   aurora.Color
	AddrStyle   aurora.Color
	VerbStyle   aurora.Color
	NounStyle   aurora.Color
	BrightStyle aurora.Color
}

func NewStyler(au aurora.Aurora) Styler {
	return Styler{
		au:          au,
		InfoStyle:   aurora.BlackFg | aurora.BrightFg,
		FailStyle:   aurora.RedFg,
		OkStyle:     aurora.GreenFg,
		WarnStyle:   aurora.YellowFg,
		AddrStyle:   aurora.BlueFg,
		VerbStyle:   aurora.MagentaFg,
		NounStyle:   aurora.CyanFg,
		BrightStyle: aurora.WhiteFg | aurora.BrightFg,
	}
}

func (s Styler) Info(str string) aurora.Value {
	return s.au.Colorize(str, s.InfoStyle)
}
func (s Styler) Fail(str string) aurora.Value {
	return s.au.Colorize(str, s.FailStyle)
}
func (s Styler) Ok(str string) aurora.Value {
	return s.au.Colorize(str, s.OkStyle)
}
func (s Styler) Warn(str string) aurora.Value {
	return s.au.Colorize(str, s.WarnStyle)
}
func (s Styler) Addr(str string) aurora.Value {
	return s.au.Colorize(str, s.AddrStyle)
}
func (s Styler) Verb(str string) aurora.Value {
	return s.au.Colorize(str, s.VerbStyle)
}
func (s Styler) Noun(str string) aurora.Value {
	return s.au.Colorize(str, s.NounStyle)
}
func (s Styler) Bright(v interface{}) aurora.Value {
	return s.au.Colorize(v, s.BrightStyle)
}

func (s Styler) UrlPath(u *url.URL) string {
	var b strings.Builder

	if len(u.EscapedPath()) > 0 {
		b.WriteString(s.Noun(u.EscapedPath()).String())
	} else {
		b.WriteString(s.Noun("/").String())
	}

	if len(u.RawQuery) > 0 {
		b.WriteString("?")
		b.WriteString(s.Verb(u.RawQuery).String())
	}

	if len(u.EscapedFragment()) > 0 {
		b.WriteString("#")
		b.WriteString(s.Addr(u.EscapedFragment()).String())
	}

	return b.String()
}
