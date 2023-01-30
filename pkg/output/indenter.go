package output

import (
	"fmt"
	"strings"
)

type IndentingBuilder struct {
	b      strings.Builder
	indent uint64
}

func (b *IndentingBuilder) Indent() {
	b.indent++
}
func (b *IndentingBuilder) Dedent() {
	if b.indent == 0 {
		panic("Trying to dedent left of 0")
	}
	b.indent--
}

func (b *IndentingBuilder) NewLine() {
	b.b.WriteString("\n")
}

// One or more whole lines
func (b *IndentingBuilder) Block(s string) {
	if b.b.Len() != 0 && b.b.String()[b.b.Len()-1] != '\n' {
		panic("Must add block at a new line")
	}
	if s[len(s)-1] != '\n' {
		panic("Added block must end in newline")
	}

	s = strings.TrimSuffix(s, "\n")
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		b.Tabs()
		b.b.WriteString(line)
		b.NewLine()
	}
}

/* Whole-line printing */

func (b *IndentingBuilder) Line(s string) {
	// TODO check for absense of new lines in the string
	b.Tabs()
	b.b.WriteString(s)
	b.NewLine()
}

func (b *IndentingBuilder) Linef(f string, a ...any) {
	// TODO check for absense of new lines in the string
	b.Tabs()
	b.b.WriteString(fmt.Sprintf(f, a...))
	b.NewLine()
}

// TODO: add variations that take a timestamp too as time.Time
// TODO: and a TabsTimestamp for starting a partial-line with a timestamp

/* Partial-line printing */

// manual tabs
func (b *IndentingBuilder) Tabs() {
	for i := uint64(0); i < b.indent; i++ {
		b.b.WriteRune('\t')
	}
}

func (b *IndentingBuilder) Print(s string) {
	b.b.WriteString(s)
}
func (b *IndentingBuilder) Printf(f string, a ...any) {
	b.b.WriteString(fmt.Sprintf(f, a...))
}
func (b *IndentingBuilder) Println(s string) {
	b.b.WriteString(s)
	b.NewLine()
}

/* Magic */

func (b *IndentingBuilder) MagicPrint(s string) {
	if b.b.Len() == 0 || b.b.String()[b.b.Len()-1] == '\n' {
		b.Tabs()
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 1 {
		for i, line := range lines[:len(lines)-1] {
			if i != 0 {
				b.Tabs()
			}
			b.b.WriteString(line)
			b.NewLine()
		}
	} else {
		b.b.WriteString(lines[0])
	}
}

/* Output */

func (b *IndentingBuilder) String() string {
	return b.b.String()
}
func (b *IndentingBuilder) Output() {
	fmt.Print(b.String())
}
