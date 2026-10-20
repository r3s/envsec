package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// setupKey installs a fresh age key in a temp dir for the duration of the test.
func setupKey(t *testing.T) string {
	t.Helper()
	keys := filepath.Join(t.TempDir(), "keys.txt")
	t.Setenv("SOPS_AGE_KEY_FILE", keys)
	if err := setKeyEnv(); err != nil {
		t.Fatalf("setKeyEnv: %v", err)
	}
	if err := ensureKey(); err != nil {
		t.Fatalf("ensureKey: %v", err)
	}
	return keys
}

func mustPub(t *testing.T) string {
	t.Helper()
	pk, err := pubkey()
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return pk
}

func TestStripOuterQuotes(t *testing.T) {
	cases := []struct{ in, want string }{
		{`A="x"`, "A=x"},
		{`A='x'`, "A=x"},
		{`A=x`, "A=x"},                     // unquoted untouched
		{`A="x`, `A="x`},                   // unbalanced quote untouched
		{`A=x"`, `A=x"`},                   // trailing quote only untouched
		{`A=`, "A="},                       // no value
		{`A=""`, "A="},                     // empty quoted value
		{`A="x"y`, `A="x"y`},               // quotes don't wrap the whole value
		{`A="x=y"`, "A=x=y"},               // quotes around value containing '='
		{`# c="x"`, `# c="x"`},             // comments are never rewritten
		{"A=\"x\"\r", "A=x"},               // CRLF line ending
		{"# note=\"x\"\r", "# note=\"x\""}, // CRLF comment untouched apart from \r
	}
	for _, c := range cases {
		if got := stripOuterQuotes(c.in); got != c.want {
			t.Errorf("stripOuterQuotes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseEnvLines(t *testing.T) {
	plain := []byte("# comment\n\nKEEP=1\nEMPTY=\nBADLINE\n")
	got := parseEnvLines(plain)
	want := []string{"KEEP=1", "EMPTY="}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseEnvLines = %v, want %v", got, want)
	}
}

func TestBuildRunEnv(t *testing.T) {
	base := []string{"PATH=/bin", "HOME=/root", "REMOVED=old"}
	plain := []byte("# c\nKEEP=1\nNEW=\nDUPE=first\nDUPE=second\n")
	got := buildRunEnv(plain, base)
	env := map[string]string{}
	for _, e := range got {
		eq := strings.IndexByte(e, '=')
		env[e[:eq]] = e[eq+1:]
	}
	want := map[string]string{"PATH": "/bin", "HOME": "/root", "REMOVED": "old", "KEEP": "1", "NEW": "", "DUPE": "second"}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("buildRunEnv = %v, want %v", env, want)
	}
}

// TestWritePlaintextPerms verifies plaintext is 0600 even when the target
// already exists with looser permissions.
func TestWritePlaintextPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(path, []byte("OLD=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePlaintext(path, []byte("NEW=2\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "NEW=2\n" {
		t.Errorf("content = %q", data)
	}
}

func TestRoundTrip(t *testing.T) {
	setupKey(t)
	plain := []byte("FOO=bar\nBAZ=\"kept as content\"\n# comment\nEMPTY=\n")
	sealed, err := encryptPlain(plain, []string{mustPub(t)})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.Contains(string(sealed), mustPub(t)) {
		t.Error("sealed file does not mention this machine's recipient")
	}
	path := filepath.Join(t.TempDir(), "test.enc.env")
	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := decryptSealed(path)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round trip mismatch:\n got %q\nwant %q", got, plain)
	}
}

func TestSealEndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupKey(t)

	// phase 1: pull script writes a quoted value that must be normalized
	pull := filepath.Join(dir, "pull.sh")
	if err := os.WriteFile(pull,
		[]byte("#!/bin/sh\nprintf 'DB_URL=\"postgres://user:pass@host/db\"\\n' > .env.local\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runSeal(".env.local", []string{"sh", pull}); err != nil {
		t.Fatalf("seal: %v", err)
	}
	sealed := ".env.local.enc.env"
	got, err := decryptSealed(sealed)
	if err != nil {
		t.Fatalf("decrypt after seal: %v", err)
	}
	if want := "DB_URL=postgres://user:pass@host/db\n"; string(got) != want {
		t.Errorf("after seal, got %q, want %q", got, want)
	}

	// phase 2: pull script appends, relying on the revealed plaintext file
	pull2 := filepath.Join(dir, "pull2.sh")
	if err := os.WriteFile(pull2,
		[]byte("#!/bin/sh\necho 'API_KEY=\"secret2\"' >> .env.local\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runSeal(".env.local", []string{"sh", pull2}); err != nil {
		t.Fatalf("re-seal: %v", err)
	}
	got, err = decryptSealed(sealed)
	if err != nil {
		t.Fatalf("decrypt after re-seal: %v", err)
	}
	want := "DB_URL=postgres://user:pass@host/db\nAPI_KEY=secret2\n"
	if string(got) != want {
		t.Errorf("after re-seal, got %q, want %q", got, want)
	}
	// no plaintext may remain behind
	if _, err := os.Stat(".env.local"); !os.IsNotExist(err) {
		t.Errorf("plaintext .env.local still exists after seal")
	}
}

// TestSealFailureRemovesPlaintext verifies that a failing pull command still
// cleans up the decrypted plaintext file.
func TestSealFailureRemovesPlaintext(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupKey(t)

	pull := filepath.Join(dir, "fail.sh")
	script := "#!/bin/sh\nprintf 'SECRET=leaked\\n' > .env.local\nexit 3\n"
	if err := os.WriteFile(pull, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	err := runSeal(".env.local", []string{"sh", pull})
	var ee exitError
	if !errors.As(err, &ee) || ee.code != 3 {
		t.Fatalf("err = %v, want exit status 3", err)
	}
	if _, err := os.Stat(".env.local"); !os.IsNotExist(err) {
		t.Error("plaintext .env.local survived a failed pull")
	}
}

// TestSealWithoutKeyRemovesPlaintext verifies the no-key error path also
// cleans up the plaintext produced by the pull script.
func TestSealWithoutKeyRemovesPlaintext(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(t.TempDir(), "absent.txt"))
	if err := setKeyEnv(); err != nil {
		t.Fatal(err)
	}
	pull := filepath.Join(dir, "pull.sh")
	script := "#!/bin/sh\nprintf 'SECRET=leaked\\n' > .env.local\n"
	if err := os.WriteFile(pull, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runSeal(".env.local", []string{"sh", pull}); err == nil {
		t.Fatal("expected an error without a key")
	}
	if _, err := os.Stat(".env.local"); !os.IsNotExist(err) {
		t.Error("plaintext .env.local survived a failed seal")
	}
}

func TestEditEndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupKey(t)

	pull := filepath.Join(dir, "pull.sh")
	if err := os.WriteFile(pull, []byte("#!/bin/sh\necho 'A=\"1\"' > .env.local\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runSeal(".env.local", []string{"sh", pull}); err != nil {
		t.Fatal(err)
	}
	sealed := ".env.local.enc.env"

	editor := filepath.Join(dir, "editor.sh")
	if err := os.WriteFile(editor,
		[]byte("#!/bin/sh\nprintf 'A=2\\nB=\"3\"\\n' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", editor)
	if err := runEdit(".env.local"); err != nil {
		t.Fatalf("edit: %v", err)
	}
	got, err := decryptSealed(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if want := "A=2\nB=3\n"; string(got) != want {
		t.Errorf("after edit, got %q, want %q", got, want)
	}
}

// TestEditNoChangeLeavesFileUntouched verifies that saving without edits does
// not rewrite (and thus dirty) the sealed file.
func TestEditNoChangeLeavesFileUntouched(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupKey(t)

	pull := filepath.Join(dir, "pull.sh")
	if err := os.WriteFile(pull, []byte("#!/bin/sh\necho 'A=1' > .env.local\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runSeal(".env.local", []string{"sh", pull}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(".env.local.enc.env")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	t.Setenv("EDITOR", "true")
	if err := runEdit(".env.local"); err != nil {
		t.Fatalf("edit: %v", err)
	}
	after, err := os.ReadFile(".env.local.enc.env")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("sealed file was rewritten although nothing changed")
	}
}

func TestExportWritesPlaintext(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupKey(t)

	sealed, err := encryptPlain([]byte("A=1\n"), []string{mustPub(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env.local.enc.env", sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runExport(".env.local"); err != nil {
		t.Fatalf("export: %v", err)
	}
	got, err := os.ReadFile(".env.local")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "A=1\n" {
		t.Errorf("export wrote %q", got)
	}
}

func TestInitCreatesKey(t *testing.T) {
	keys := filepath.Join(t.TempDir(), "keys.txt")
	t.Setenv("SOPS_AGE_KEY_FILE", keys)
	if err := setKeyEnv(); err != nil {
		t.Fatal(err)
	}
	if err := runInit(); err != nil {
		t.Fatalf("init: %v", err)
	}
	data, err := os.ReadFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "AGE-SECRET-KEY-1") {
		t.Errorf("key file does not contain a secret key line")
	}
	if pk := mustPub(t); !strings.HasPrefix(pk, "age1") {
		t.Errorf("pubkey %q does not look like an age public key", pk)
	}
}

func TestKeyFilePermissions(t *testing.T) {
	keys := setupKey(t)
	info, err := os.Stat(keys)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key file mode = %o, want 600", got)
	}
}

// TestInitFixesLooseKeyPerms verifies init tightens a key file that is too open.
func TestInitFixesLooseKeyPerms(t *testing.T) {
	keys := setupKey(t)
	if err := os.Chmod(keys, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runInit(); err != nil {
		t.Fatalf("init: %v", err)
	}
	info, err := os.Stat(keys)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("after init, key mode = %o, want 600", got)
	}
}

// TestDoctorSurvivesCorruptKey verifies doctor reports a broken key instead of
// exiting.
func TestDoctorSurvivesCorruptKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOPS_AGE_KEY_FILE", path)
	if err := setKeyEnv(); err != nil {
		t.Fatal(err)
	}
	if err := runDoctor(); err != nil {
		t.Errorf("doctor returned error: %v", err)
	}
}

// TestAddRecipient simulates two machines: A seals a file, grants B access,
// and B can then decrypt it.
func TestAddRecipient(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	keyA := setupKey(t)
	aPub := mustPub(t)

	keyB := filepath.Join(t.TempDir(), "keys.txt")
	t.Setenv("SOPS_AGE_KEY_FILE", keyB)
	if err := setKeyEnv(); err != nil {
		t.Fatal(err)
	}
	if err := ensureKey(); err != nil {
		t.Fatalf("ensureKey (B): %v", err)
	}
	bPub := mustPub(t)

	t.Setenv("SOPS_AGE_KEY_FILE", keyA)
	if err := setKeyEnv(); err != nil {
		t.Fatal(err)
	}
	sealed, err := encryptPlain([]byte("SECRET=value\n"), []string{aPub})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.WriteFile(".env.local.enc.env", sealed, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SOPS_AGE_KEY_FILE", keyB)
	if err := setKeyEnv(); err != nil {
		t.Fatal(err)
	}
	if _, err := decryptSealed(".env.local.enc.env"); err == nil {
		t.Fatal("B could decrypt before being granted access")
	}

	t.Setenv("SOPS_AGE_KEY_FILE", keyA)
	if err := setKeyEnv(); err != nil {
		t.Fatal(err)
	}
	if err := runAddRecipient(".env.local", []string{bPub}); err != nil {
		t.Fatalf("addrecipient: %v", err)
	}

	recs, err := recipientsFromSealed(".env.local.enc.env")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recs, []string{aPub, bPub}) {
		t.Errorf("recipients after add = %v, want %v", recs, []string{aPub, bPub})
	}

	t.Setenv("SOPS_AGE_KEY_FILE", keyB)
	if err := setKeyEnv(); err != nil {
		t.Fatal(err)
	}
	got, err := decryptSealed(".env.local.enc.env")
	if err != nil {
		t.Fatalf("B could not decrypt after grant: %v", err)
	}
	if string(got) != "SECRET=value\n" {
		t.Errorf("B got %q", got)
	}
	t.Setenv("SOPS_AGE_KEY_FILE", keyA)
	if err := setKeyEnv(); err != nil {
		t.Fatal(err)
	}
	if _, err := decryptSealed(".env.local.enc.env"); err != nil {
		t.Fatalf("A lost access after grant: %v", err)
	}

	// granting the same key again is a no-op
	if err := runAddRecipient(".env.local", []string{bPub}); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	recs, _ = recipientsFromSealed(".env.local.enc.env")
	if !reflect.DeepEqual(recs, []string{aPub, bPub}) {
		t.Errorf("recipients after duplicate add = %v", recs)
	}

	if err := runAddRecipient(".env.local", []string{"not-an-age-key"}); err == nil {
		t.Fatal("invalid pubkey was accepted")
	}
}
