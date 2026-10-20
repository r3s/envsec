package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/spf13/cobra"
)

func newAddRecipientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "addrecipient [-f FILE] PUBKEY...",
		Short: "grant other machines access to FILE.enc.env",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("no public key given — usage: envsec addrecipient [-f FILE] PUBKEY...")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			return runAddRecipient(fileFlag(c), args)
		},
	}
	cmd.Flags().StringP("file", "f", ".env.local", "secrets file")
	return cmd
}

// runAddRecipient grants additional machines access to a sealed file by
// re-encrypting it to the existing recipients plus the given public keys.
// Existing recipients are always preserved — never silently dropped.
func runAddRecipient(envfile string, pubkeys []string) error {
	sealed := envfile + ".enc.env"
	if _, err := os.Stat(sealed); err != nil {
		fatal("no sealed file %s — run 'envsec seal' first", sealed)
	}

	plain, err := decryptSealed(sealed)
	if err != nil {
		return err
	}
	groups, err := keyGroupsFromSealed(sealed)
	if err != nil {
		return err
	}

	// append new keys to the last group (files created by envsec have one)
	have := map[string]bool{}
	for _, g := range groups {
		for _, k := range g {
			have[k.ToString()] = true
		}
	}
	last := len(groups) - 1
	var added []string
	for _, pk := range pubkeys {
		if have[pk] {
			continue
		}
		mk, err := sopsage.MasterKeyFromRecipient(pk)
		if err != nil {
			return fmt.Errorf("invalid age public key %q: %w", pk, err)
		}
		groups[last] = append(groups[last], mk)
		have[pk] = true
		added = append(added, pk)
	}

	if len(added) == 0 {
		fmt.Println("no new recipients — all given keys already have access")
		return nil
	}

	out, err := encryptPlainWithKeyGroups(plain, groups)
	if err != nil {
		return err
	}
	if err := atomicWrite(sealed, out); err != nil {
		return err
	}
	color.Green("added %d recipient(s) to %s", len(added), sealed)
	for _, pk := range added {
		fmt.Println("  " + color.CyanString(pk))
	}
	return nil
}
