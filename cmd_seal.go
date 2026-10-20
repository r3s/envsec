package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"github.com/fatih/color"
	"github.com/getsops/sops/v3"
	"github.com/spf13/cobra"
)

func newSealCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "seal [-f FILE] -- CMD...",
		Short: "run your pull script, then (re)encrypt to FILE.enc.env",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("nothing to run — usage: envsec seal [-f FILE] -- <pull command>")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			return runSeal(fileFlag(c), args)
		},
	}
	cmd.Flags().StringP("file", "f", ".env.local", "secrets file")
	return cmd
}

// runSeal runs the repo's pull script against a plaintext .env file revealed
// from (or created next to) the sealed file, then re-encrypts atomically.
// Any plaintext left behind is removed on exit, error, or Ctrl-C.
func runSeal(envfile string, pull []string) error {
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

	// reveal existing secrets so partial pull scripts see the full file
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

	// run the repo's pull script (edits envfile in place)
	if err := runPull(pull); err != nil {
		return err
	}

	if _, err := os.Stat(envfile); err != nil {
		fatal("pull command produced no %s", envfile)
	}

	raw, err := os.ReadFile(envfile)
	if err != nil {
		return err
	}
	norm := normalizeDotenv(raw)

	var sealedBytes []byte
	if len(keyGroups) > 0 {
		// keep every existing recipient, so re-sealing never locks anyone out
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
	color.Green("sealed -> %s", sealed)
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
