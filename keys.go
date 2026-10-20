package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
)

// keyfile returns the machine's age private key path: $SOPS_AGE_KEY_FILE if
// set, else ~/.config/sops/age/keys.txt (the sops CLI / age keysource default).
func keyfile() (string, error) {
	if f := os.Getenv("SOPS_AGE_KEY_FILE"); f != "" {
		return f, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".config", "sops", "age", "keys.txt"), nil
}

// setKeyEnv exports SOPS_AGE_KEY_FILE so sops' age keysource finds the key.
func setKeyEnv() error {
	path, err := keyfile()
	if err != nil {
		return err
	}
	return os.Setenv("SOPS_AGE_KEY_FILE", path)
}

// ensureKey generates a fresh age key at the keyfile path unless one exists,
// and tightens the permissions of an existing key.
func ensureKey() error {
	path, err := keyfile()
	if err != nil {
		return err
	}
	if data, err := os.ReadFile(path); err == nil {
		if _, err := age.ParseIdentities(bytes.NewReader(data)); err == nil {
			_, err := fixKeyPerms(path)
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cannot create key dir: %w", err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("cannot generate age key: %w", err)
	}
	lines := fmt.Sprintf("# created: %s\n# public key: %s\n%s\n",
		time.Now().UTC().Format(time.RFC3339), id.Recipient().String(), id.String())
	if err := writePlaintext(path, []byte(lines)); err != nil {
		return fmt.Errorf("cannot write key to %s: %w", path, err)
	}
	return nil
}

// fixKeyPerms forces path to 0600, reporting whether a change was needed.
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

// pubkey returns this machine's age public key derived from the private key.
func pubkey() (string, error) {
	path, err := keyfile()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("no key at %s — run 'envsec init' on this machine", path)
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil || len(ids) == 0 {
		return "", fmt.Errorf("cannot parse key at %s (%v) — re-run 'envsec init'", path, err)
	}
	id, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return "", fmt.Errorf("key at %s is not a native age identity", path)
	}
	return id.Recipient().String(), nil
}
