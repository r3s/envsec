package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// cmdRun decrypts the sealed file in memory and execs CMD with the secrets
// injected into the environment. Secrets never touch disk; exit codes and
// signals pass through to the caller via exec(3).
func cmdRun(args []string) error {
	envfile, cmd := parseFlags(args)
	if len(cmd) == 0 {
		fatal("nothing to run — usage: envsec run [-f FILE] -- <command>")
	}
	sealed := envfile + ".enc.env"
	if _, err := os.Stat(sealed); err != nil {
		fatal("no sealed file %s — run 'envsec seal' first", sealed)
	}
	plain, err := decryptSealed(sealed)
	if err != nil {
		return err
	}
	return execWithEnv(cmd, plain)
}

// execWithEnv replaces the current process with cmd, mirroring sops exec-env:
// the base environment is kept, and decrypted KEY=VALUE lines override it.
func execWithEnv(cmd []string, plain []byte) error {
	argv0 := cmd[0]
	if !strings.ContainsRune(argv0, '/') {
		// syscall.Exec is raw execve(2), which does not search $PATH.
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
