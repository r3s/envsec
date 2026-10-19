// Command envsec manages per-machine encrypted .env files using sops + age.
package main

import (
	"fmt"
	"os"
)

const usageText = `envsec — per-machine encrypted .env workflow (sops + age, compiled in)

USAGE
    envsec <command> [flags] [-f FILE] [-- cmd...]

SETUP  (once per machine)
    init             generate this machine's age key, print its public key
    doctor           show key status and embedded sops/age versions

SECRETS
    seal [-f FILE] -- CMD...   run a pull script, then (re)encrypt to FILE.enc.env
    run  [-f FILE] -- CMD...   decrypt in memory and run CMD with the secrets
    edit [-f FILE]             open sealed secrets in $EDITOR, re-encrypt on save
    export [-f FILE]           write decrypted secrets to FILE on disk (debug only)

ACCESS
    addrecipient [-f FILE] PUBKEY...   grant other machines access to FILE.enc.env

FLAGS
    -f, --file FILE   secrets file (default: .env.local); sealed file: FILE.enc.env

EXAMPLES
    envsec init
    envsec seal -- ./scripts/pull-secrets.sh
    envsec run -- npm run dev
    envsec addrecipient age1mn2...
    envsec edit

FIRST-TIME FLOW
    1. envsec init                 # once per machine
    2. envsec seal -- <pull cmd>   # fetch & encrypt, commit FILE.enc.env
    3. envsec run -- <cmd>         # daily use; secrets never touch disk
    Team mates: they send you the public key from 'envsec doctor', you run
    'envsec addrecipient <pubkey>', they pull and run.

KEY
    Private: $SOPS_AGE_KEY_FILE or ~/.config/sops/age/keys.txt  (back it up)
    Public:  'envsec doctor' / 'envsec init' — safe to share.
`

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "envsec: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Print(usageText)
}

func main() {
	// sops resolves age identities from SOPS_AGE_KEY_FILE; export it so
	// encrypt/decrypt pick up the machine key.
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
	case "addrecipient":
		err = cmdAddRecipient(args[1:])
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
