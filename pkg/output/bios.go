package output

import "github.com/go-logr/logr"

type Bios interface {
	// Increased verbosity stuff - the default output should be fine if everthing works, just printing the details. The increased verbosity level is for adding more info so you can see how far it got if it failed (but app-level failed, eg print that incoming connection was accepted, so if http-log never prints anything, you know we accepted and the client failed to send)
	Trace(msg string, keysAndValues ...interface{})
	TraceWithName(name, msg string, keysAndValues ...interface{})
	// system/admin stuff, think of this as writing to a log file. Eg tracing through tough algos. Not eg errors opening user-defined files cause that's part of the UI
	GetLogger() logr.Logger

	PrintOk(msg string)
	PrintInfo(msg string)
	PrintWarn(msg string)
	PrintErr(msg string)

	CheckInfo(err error) bool
	CheckWarn(err error) bool
	CheckErr(err error)
}
