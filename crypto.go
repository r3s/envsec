package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/keyservice"
	dotenvstore "github.com/getsops/sops/v3/stores/dotenv"
	"github.com/getsops/sops/v3/version"
)

// decryptSealed decrypts a sops-encrypted dotenv file in memory. Identities
// are resolved by the age keysource from SOPS_AGE_KEY_FILE (set in main).
func decryptSealed(path string) ([]byte, error) {
	plain, err := decrypt.File(path, "dotenv")
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", path, err)
	}
	return plain, nil
}

func encryptPlain(plain []byte, recipients []string) ([]byte, error) {
	keys, err := sopsage.MasterKeysFromRecipients(strings.Join(recipients, ","))
	if err != nil {
		return nil, fmt.Errorf("parse recipients: %w", err)
	}
	group := make(sops.KeyGroup, 0, len(keys))
	for _, k := range keys {
		group = append(group, k)
	}
	return encryptPlainWithKeyGroups(plain, []sops.KeyGroup{group})
}

// encryptPlainWithKeyGroups encrypts plaintext dotenv, (re)using the exact
// key groups of an existing sealed file. This keeps every existing recipient
// on re-seal/edit instead of silently re-encrypting to one key.
func encryptPlainWithKeyGroups(plain []byte, keyGroups []sops.KeyGroup) ([]byte, error) {
	store := &dotenvstore.Store{}
	branches, err := store.LoadPlainFile(plain)
	if err != nil {
		return nil, fmt.Errorf("parse dotenv: %w", err)
	}
	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: keyGroups,
			Version:   version.Version,
		},
	}

	svcs := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(svcs)
	if len(errs) > 0 {
		return nil, fmt.Errorf("generate data key: %v", errs[0])
	}

	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("encrypt tree: %w", err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(
		mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("encrypt MAC: %w", err)
	}

	sealed, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("emit sealed dotenv: %w", err)
	}
	return sealed, nil
}

// keyGroupsFromSealed rebuilds fresh master keys from a sealed file's
// metadata (they carry no encrypted data key yet), preserving structure.
func keyGroupsFromSealed(path string) ([]sops.KeyGroup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	store := &dotenvstore.Store{}
	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	groups := make([]sops.KeyGroup, 0, len(tree.Metadata.KeyGroups))
	for _, group := range tree.Metadata.KeyGroups {
		ng := make(sops.KeyGroup, 0, len(group))
		for _, k := range group {
			mk, err := sopsage.MasterKeyFromRecipient(k.ToString())
			if err != nil {
				return nil, fmt.Errorf("unsupported master key %q: %w", k.ToString(), err)
			}
			ng = append(ng, mk)
		}
		groups = append(groups, ng)
	}
	return groups, nil
}

func recipientsFromSealed(path string) ([]string, error) {
	groups, err := keyGroupsFromSealed(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, g := range groups {
		for _, k := range g {
			out = append(out, k.ToString())
		}
	}
	return out, nil
}

// atomicWrite writes data to path via a temp file + rename, so a crash can
// never leave a partial sealed file in place.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".seal-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// writePlaintext writes a plaintext file the pull script can read; 0600 keeps
// secrets private even under a permissive umask.
func writePlaintext(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// stripOuterQuotes drops matching surrounding quotes so values match dotenv
// semantics when loaded.
func stripOuterQuotes(line string) string {
	eq := strings.IndexByte(line, '=')
	if eq <= 0 || len(line) <= eq+2 {
		return line
	}
	key, val := line[:eq], line[eq+1:]
	if len(val) >= 2 {
		if (val[0] == '"' && val[len(val)-1] == '"') ||
			(val[0] == '\'' && val[len(val)-1] == '\'') {
			return key + "=" + val[1:len(val)-1]
		}
	}
	return line
}

func normalizeDotenv(data []byte) []byte {
	lines := bytes.Split(data, []byte("\n"))
	for i, line := range lines {
		lines[i] = []byte(stripOuterQuotes(string(line)))
	}
	return bytes.Join(lines, []byte("\n"))
}

func parseEnvLines(plain []byte) []string {
	var out []string
	for _, line := range strings.Split(string(plain), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.IndexByte(line, '=') <= 0 {
			continue
		}
		out = append(out, line)
	}
	return out
}
