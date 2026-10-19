package main

import (
	"fmt"
	"os"
)

// cmdExport decrypts the sealed file back to a plaintext file on disk. Debug
// only: it prints a reminder to delete the plaintext when done.
func cmdExport(args []string) error {
	envfile, _ := parseFlags(args)
	sealed := envfile + ".enc.env"
	if _, err := os.Stat(sealed); err != nil {
		fatal("no sealed file %s — run 'envsec seal' first", sealed)
	}
	plain, err := decryptSealed(sealed)
	if err != nil {
		return err
	}
	if err := writePlaintext(envfile, plain); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote PLAINTEXT -> %s  (delete it when done: rm %s)\n", envfile, envfile)
	return nil
}
