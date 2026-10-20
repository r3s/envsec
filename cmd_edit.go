package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/spf13/cobra"
)

func newEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit [-f FILE]",
		Short: "open sealed secrets in $EDITOR, re-encrypt on save",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runEdit(fileFlag(c))
		},
	}
	cmd.Flags().StringP("file", "f", ".env.local", "secrets file")
	return cmd
}

// runEdit decrypts the sealed file to a 0600 temp file, opens $EDITOR on it,
// and re-encrypts on save. When the sealed file does not exist yet it is
// created, encrypted to this machine's public key.
func runEdit(envfile string) error {
	sealed := envfile + ".enc.env"

	var plain []byte
	var keyGroups []sops.KeyGroup
	if _, err := os.Stat(sealed); err == nil {
		groups, err := keyGroupsFromSealed(sealed)
		if err != nil {
			return err
		}
		keyGroups = groups
		plain, err = decryptSealed(sealed)
		if err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(sealed), ".edit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(plain); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := runEditor(os.Getenv("EDITOR"), tmpName); err != nil {
		return err
	}

	edited, err := os.ReadFile(tmpName)
	if err != nil {
		return err
	}

	var sealedBytes []byte
	if len(keyGroups) > 0 {
		sealedBytes, err = encryptPlainWithKeyGroups(edited, keyGroups)
	} else {
		sealedBytes, err = encryptPlain(edited, []string{pubkey()})
	}
	if err != nil {
		return err
	}
	return atomicWrite(sealed, sealedBytes)
}

// runEditor invokes $EDITOR on path, falling back to vi. Arguments embedded
// in the editor string (e.g. "code -w") are split on whitespace.
func runEditor(editor, path string) error {
	if editor == "" {
		editor = "vi"
	}
	parts := strings.Fields(editor)
	args := append(parts[1:], path)
	c := exec.Command(parts[0], args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("editor %q failed: %w", parts[0], err)
	}
	return nil
}
