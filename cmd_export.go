package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export [-f FILE]",
		Short: "write decrypted secrets to FILE on disk (debug only)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runExport(fileFlag(c))
		},
	}
	cmd.Flags().StringP("file", "f", ".env.local", "secrets file")
	return cmd
}

// runExport decrypts the sealed file back to a plaintext file on disk. Debug
// only: it prints a reminder to delete the plaintext when done.
func runExport(envfile string) error {
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
