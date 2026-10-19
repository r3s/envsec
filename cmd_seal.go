package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"github.com/getsops/sops/v3"
)

// cmdSeal runs the repo's pull script against a plaintext .env file revealed
// from (or created next to) the sealed file, then re-encrypts atomically.
// Any plaintext left behind is removed on exit, error, or Ctrl-C.
func cmdSeal(args []string) error {
	envfile, cmd := parseFlags(args)
	if len(cmd) == 0 {
		fatal("nothing to run — usage: envsec seal [-f FILE] -- <pull command>")
	}
	sealed := envfile + ".enc.env"

	// Clean up plaintext however we exit.
	cleanup := func() { os.Remove(envfile) }
	defer cleanup()
	done := make(chan struct{})
	defer close(done)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		select {
		case <-done:
		case <-sig:
			cleanup()
			os.Exit(130)
		}
	}()

	// 1. reveal current secrets so partial pull scripts see the full file
	var keyGroups []sops.KeyGroup
	if _, err := os.Stat(sealed); err == nil {
		groups, err := keyGroupsFromSealed(sealed)
		if err != nil {
			return err
		}
		keyGroups = groups
		plain, err := decryptSealed(sealed)
		if err != nil {
			return err
		}
		if err := writePlaintext(envfile, plain); err != nil {
			return err
		}
	}

	// 2. run the repo's own pull script (edits ENVFILE in place)
	if err := runPull(cmd); err != nil {
		return err
	}

	// 3. the pull must have produced the file
	if _, err := os.Stat(envfile); err != nil {
		fatal("pull command produced no %s", envfile)
	}

	// 4. normalize matching outer quotes, re-encrypt atomically
	raw, err := os.ReadFile(envfile)
	if err != nil {
		return err
	}
	norm := normalizeDotenv(raw)

	var sealedBytes []byte
	if len(keyGroups) > 0 {
		// keep every recipient that was there before, so re-sealing can
		// never silently lock out team members
		sealedBytes, err = encryptPlainWithKeyGroups(norm, keyGroups)
	} else {
		sealedBytes, err = encryptPlain(norm, []string{pubkey()})
	}
	if err != nil {
		return err
	}
	if err := atomicWrite(sealed, sealedBytes); err != nil {
		return err
	}
	fmt.Println("sealed ->", sealed)
	return nil
}

// runPull executes the pull command with inherited stdio and propagates its
// exit status.
func runPull(cmd []string) error {
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := c.Run()
	if err == nil {
		return nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		os.Exit(ee.ExitCode())
	}
	return fmt.Errorf("pull command failed: %w", err)
}
