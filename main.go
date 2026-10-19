// Command envsec manages per-machine encrypted .env files using sops + age.
//
// envx — per-machine encrypted .env workflow using sops + age
//
//	envsec init                     set up this machine (generate a key)
//	envsec doctor                   check key, print this machine's public key
//	envsec seal [-f FILE] -- CMD... run your repo's pull script, then (re)encrypt the result
//	envsec run  [-f FILE] -- CMD... decrypt in memory and run CMD with secrets injected
//	envsec edit [-f FILE]           open the sealed secrets in $EDITOR, re-encrypt on save
//	envsec export [-f FILE]         decrypt back to a plaintext file on disk (debug only)
//
// The sealed file for FILE is "FILE.enc.env" (default FILE is .env.local).
// Nothing here is machine-specific: the public key is derived from the local
// private key at ~/.config/sops/age/keys.txt, so this binary is safe to commit.
package main

import (
	"fmt"
	"os"
)

const usageText = `envsec — per-machine encrypted .env workflow using sops + age

  envsec init                     set up this machine (generate a key)
  envsec doctor                   check key, print this machine's public key
  envsec seal [-f FILE] -- CMD... run your repo's pull script, then (re)encrypt the result
  envsec run  [-f FILE] -- CMD... decrypt in memory and run CMD with secrets injected
  envsec edit [-f FILE]           open the sealed secrets in $EDITOR, re-encrypt on save
  envsec export [-f FILE]         decrypt back to a plaintext file on disk (debug only)

The sealed file for FILE is "FILE.enc.env" (default FILE is .env.local).
Secrets are held in memory (run) or in plaintext files that are removed on
exit (seal/edit/export); encrypted output is written atomically.
`

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "envsec: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Print(usageText)
}

func main() {
	// The age keysource inside sops resolves identities from SOPS_AGE_KEY_FILE.
	// Set it up-front (as the bash envx did) so decrypt/encrypt see our key.
	setKeyEnv()

	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		return
	}
	var err error
	switch args[0] {
	case "init":
		err = cmdInit()
	case "doctor":
		err = cmdDoctor()
	case "seal":
		err = cmdSeal(args[1:])
	case "run":
		err = cmdRun(args[1:])
	case "edit":
		err = cmdEdit(args[1:])
	case "export":
		err = cmdExport(args[1:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fatal("unknown command %q (try: envsec help)", args[0])
	}
	if err != nil {
		fatal("%v", err)
	}
}
