package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
)

// keyfile returns the path of the machine's age private key. Like the bash
// envx, it honors SOPS_AGE_KEY_FILE and defaults to ~/.config/sops/age/keys.txt
// (the same location the sops CLI / age keysource use).
func keyfile() string {
	if f := os.Getenv("SOPS_AGE_KEY_FILE"); f != "" {
		return f
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fatal("cannot determine home directory: %v", err)
	}
	return filepath.Join(home, ".config", "sops", "age", "keys.txt")
}

// setKeyEnv exports SOPS_AGE_KEY_FILE so the sops age keysource (and therefore
// decrypt/encrypt) picks up our machine key, exactly like envx did.
func setKeyEnv() {
	os.Setenv("SOPS_AGE_KEY_FILE", keyfile())
}

// ensureKey generates a fresh age key at the keyfile path unless one exists.
// The private identity is written in the age keys.txt format and the file is
// forced to owner read/write only (0600), independent of umask.
func ensureKey() error {
	path := keyfile()
	if data, err := os.ReadFile(path); err == nil {
		if _, err := age.ParseIdentities(bytes.NewReader(data)); err == nil {
			// key exists and is parseable; only tighten permissions if loose
			_, err := fixKeyPerms(path)
			return err
		}
	}
	// No usable key yet: generate one.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cannot create key dir: %w", err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("cannot generate age key: %w", err)
	}
	lines := fmt.Sprintf("# created: %s\n# public key: %s\n%s\n",
		time.Now().UTC().Format(time.RFC3339), id.Recipient().String(), id.String())
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		return fmt.Errorf("cannot write key to %s: %w", path, err)
	}
	// Make the mode explicit: os.WriteFile's mode is masked by umask, which
	// could otherwise leave the key unreadable by its owner (e.g. umask 0700).
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("cannot set key permissions on %s: %w", path, err)
	}
	return nil
}

// fixKeyPerms forces the key file to owner read/write only (0600) and reports
// whether a change was needed. It is a no-op when the permission is already
// correct, so it is safe to run on every init.
func fixKeyPerms(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if info.Mode().Perm() == 0o600 {
		return false, nil
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return false, fmt.Errorf("cannot chmod key %s to 0600: %w", path, err)
	}
	return true, nil
}

// pubkey returns this machine's age public key derived from the private key at
// keyfile(), or exits with an error if the key is missing.
func pubkey() string {
	data, err := os.ReadFile(keyfile())
	if err != nil {
		fatal("no key at %s — run 'envsec init' on this machine", keyfile())
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil || len(ids) == 0 {
		fatal("cannot parse key at %s (%v) — re-run 'envsec init'", keyfile(), err)
	}
	id, ok := ids[0].(*age.X25519Identity)
	if !ok {
		fatal("key at %s is not a native age identity", keyfile())
	}
	return id.Recipient().String()
}
