package main

import (
	"flag"
	"io"
	"os"
)

// parseFlags handles "[-f FILE] -- CMD...": flags before "--" (or before the
// first non-flag arg) are options; everything after starts the command.
func parseFlags(args []string) (envfile string, rest []string) {
	fs := flag.NewFlagSet("envsec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := fs.String("f", ".env.local", "secrets file")
	fs.StringVar(f, "file", ".env.local", "secrets file")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			usage()
			os.Exit(0)
		}
		fatal("%v", err)
	}
	return *f, fs.Args()
}
