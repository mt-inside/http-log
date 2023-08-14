package bios

type Bios interface {
	Version()

	PrintOk(msg string)
	PrintInfo(msg string)
	PrintWarn(msg string)
	PrintErr(msg string)

	CheckPrintInfo(err error) bool
	CheckPrintWarn(err error) bool
	CheckPrintErr(err error) bool

	Unwrap(err error)
}
