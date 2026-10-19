package main

import (
	"fmt"
	"os"

	sopsage "github.com/getsops/sops/v3/age"
)

// cmdAddRecipient grants additional machines access to a sealed file by
// re-encrypting it to the existing recipients plus the given public keys.
// Existing recipients are always preserved — never silently dropped.
func cmdAddRecipient(args []string) error {
	envfile, rest := parseFlags(args)
	if len(rest) == 0 {
		fatal("usage: envsec addrecipient [-f FILE] PUBKEY...")
	}
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
	for _, pk := range rest {
		if have[pk] {
			continue // already has access
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
	fmt.Printf("added %d recipient(s) to %s:\n", len(added), sealed)
	for _, pk := range added {
		fmt.Println("  " + pk)
	}
	return nil
}
