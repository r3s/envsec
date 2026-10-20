package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/getsops/sops/v3"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "generate this machine's age key, print its public key",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runInit()
		},
	}
}

func runInit() error {
	path, err := keyfile()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		fmt.Println("==> key already exists at", path)
		if fixed, err := fixKeyPerms(path); err != nil {
			return err
		} else if fixed {
			fmt.Println("    permissions were loose — tightened to 0600")
		}
	} else {
		fmt.Println("==> generating a new per-machine key")
		if err := ensureKey(); err != nil {
			return err
		}
	}
	pk, err := pubkey()
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("This machine's PUBLIC key (safe to share):", color.CyanString(pk))
	fmt.Println("PRIVATE key lives at:", path, "(back this up to your password manager)")
	return nil
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "show key status and embedded sops/age versions",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDoctor()
		},
	}
}

func runDoctor() error {
	path, err := keyfile()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		fmt.Println("key:   ", path)
		if pk, err := pubkey(); err != nil {
			fmt.Println("pubkey: INVALID —", err)
		} else {
			fmt.Println("pubkey:", color.CyanString(pk))
		}
	} else {
		fmt.Println("key:   MISSING — run 'envsec init'")
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			switch d.Path {
			case "github.com/getsops/sops/v3":
				fmt.Println("sops:  ", d.Version)
			case "filippo.io/age":
				fmt.Println("age:   ", d.Version)
			}
		}
	}
	return nil
}

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
	addFileFlag(cmd)
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// runSeal reveals the current secrets, lets the pull script update them, and
// re-encrypts the result. The plaintext copy is removed on every exit path.
func runSeal(envfile string, pull []string) error {
	sealed := envfile + ".enc.env"
	cleanup := func() { os.Remove(envfile) }
	defer cleanup()
	defer onInterrupt(cleanup)()

	var groups []sops.KeyGroup
	if _, err := os.Stat(sealed); err == nil {
		plain, g, err := loadSealed(sealed)
		if err != nil {
			return err
		}
		groups = g
		if err := writePlaintext(envfile, plain); err != nil {
			return err
		}
	}

	if err := runPull(pull); err != nil {
		return err
	}

	raw, err := os.ReadFile(envfile)
	if err != nil {
		return fmt.Errorf("pull command produced no %s: %w", envfile, err)
	}
	if err := writeSealed(sealed, normalizeDotenv(raw), groups); err != nil {
		return err
	}
	color.Green("sealed -> %s", sealed)
	return nil
}

// runPull runs the pull command with inherited stdio, preserving its exit code.
func runPull(cmd []string) error {
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := c.Run()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return exitError{code: ee.ExitCode()}
	}
	return fmt.Errorf("pull command failed: %w", err)
}

func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [-f FILE] -- CMD...",
		Short: "decrypt in memory and run CMD with the secrets",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("nothing to run — usage: envsec run [-f FILE] -- <command>")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			return runWithSecrets(fileFlag(c), args)
		},
	}
	addFileFlag(cmd)
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func runWithSecrets(envfile string, cmd []string) error {
	sealed := envfile + ".enc.env"
	if _, err := os.Stat(sealed); err != nil {
		return fmt.Errorf("no sealed file %s — run 'envsec seal' first", sealed)
	}
	plain, err := decryptSealed(sealed)
	if err != nil {
		return err
	}
	return execWithEnv(cmd, plain)
}

// execWithEnv replaces the current process with cmd, with the decrypted
// KEY=VALUE lines overriding the base environment.
func execWithEnv(cmd []string, plain []byte) error {
	argv0 := cmd[0]
	// syscall.Exec is raw execve(2), which does not search $PATH
	if !strings.ContainsRune(argv0, '/') {
		resolved, err := exec.LookPath(argv0)
		if err != nil {
			return err
		}
		argv0 = resolved
	}
	if err := syscall.Exec(argv0, cmd, buildRunEnv(plain, os.Environ())); err != nil {
		return fmt.Errorf("exec %s: %w", cmd[0], err)
	}
	return nil
}

// buildRunEnv merges decrypted dotenv lines over a base environment. Values
// from the file win; duplicate keys in the file keep the last occurrence.
func buildRunEnv(plain []byte, base []string) []string {
	overrides := map[string]string{}
	var order []string
	for _, line := range parseEnvLines(plain) {
		eq := strings.IndexByte(line, '=')
		k := line[:eq]
		if _, dup := overrides[k]; !dup {
			order = append(order, k)
		}
		overrides[k] = line
	}
	env := make([]string, 0, len(base)+len(order))
	for _, e := range base {
		eq := strings.IndexByte(e, '=')
		if eq < 0 {
			continue
		}
		if _, dup := overrides[e[:eq]]; dup {
			continue
		}
		env = append(env, e)
	}
	for _, k := range order {
		env = append(env, overrides[k])
	}
	return env
}

func newEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit [-f FILE]",
		Short: "open sealed secrets in $EDITOR, re-encrypt on save",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runEdit(fileFlag(c))
		},
	}
	addFileFlag(cmd)
	return cmd
}

// runEdit decrypts to a 0600 temp file, opens $EDITOR, and re-encrypts only if
// the content changed.
func runEdit(envfile string) error {
	sealed := envfile + ".enc.env"

	var plain []byte
	var groups []sops.KeyGroup
	exists := false
	if _, err := os.Stat(sealed); err == nil {
		exists = true
		var err error
		plain, groups, err = loadSealed(sealed)
		if err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(sealed), ".edit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	defer os.Remove(tmpName)
	defer onInterrupt(func() { os.Remove(tmpName) })()
	if err := writePlaintext(tmpName, plain); err != nil {
		return err
	}

	if err := runEditor(os.Getenv("EDITOR"), tmpName); err != nil {
		return err
	}

	edited, err := os.ReadFile(tmpName)
	if err != nil {
		return err
	}
	if exists && bytes.Equal(edited, plain) {
		return nil
	}
	return writeSealed(sealed, normalizeDotenv(edited), groups)
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

func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export [-f FILE]",
		Short: "write decrypted secrets to FILE on disk (debug only)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runExport(fileFlag(c))
		},
	}
	addFileFlag(cmd)
	return cmd
}

func runExport(envfile string) error {
	sealed := envfile + ".enc.env"
	if _, err := os.Stat(sealed); err != nil {
		return fmt.Errorf("no sealed file %s — run 'envsec seal' first", sealed)
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
	addFileFlag(cmd)
	return cmd
}

// runAddRecipient re-encrypts the sealed file to its existing recipients plus
// the given public keys. Existing recipients are never dropped.
func runAddRecipient(envfile string, pubkeys []string) error {
	sealed := envfile + ".enc.env"
	if _, err := os.Stat(sealed); err != nil {
		return fmt.Errorf("no sealed file %s — run 'envsec seal' first", sealed)
	}

	plain, groups, err := loadSealed(sealed)
	if err != nil {
		return err
	}

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

	if err := writeSealed(sealed, plain, groups); err != nil {
		return err
	}
	color.Green("added %d recipient(s) to %s", len(added), sealed)
	for _, pk := range added {
		fmt.Println("  " + color.CyanString(pk))
	}
	return nil
}
