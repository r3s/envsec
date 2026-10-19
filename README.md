# envsec

Per-machine encrypted `.env` workflow using [sops](https://github.com/getsops/sops) + [age](https://age-encryption.org), as a single static Go binary. No other tools are required — sops and age are compiled in as Go libraries.

## Why

- Secrets live in the repo as a **sealed dotenv file** (`FILE.enc.env`), safe to commit.
- Each machine has its **own age key** (`~/.config/sops/age/keys.txt`), so only authorized machines can decrypt.
- Nothing is machine-specific in the repo: the public key is derived from the local private key.
- **Offline.** No server, no SaaS, no vendor lock-in (age & sops are open standards; you can decrypt your files with the `age`/`sops` CLIs directly).

## Install

```sh
go install github.com/r3s/envsec@latest
```

For a release build (smaller static binary):

```sh
make release   # CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"
```

## Usage

```sh
envsec init                     # generate a per-machine key (first time only)
envsec doctor                   # show key status + embedded sops/age versions
envsec seal [-f FILE] -- CMD... # run your pull script, then (re)encrypt
envsec run  [-f FILE] -- CMD... # decrypt in memory, run CMD with secrets injected
envsec edit [-f FILE]           # open sealed secrets in $EDITOR, re-encrypt on save
envsec export [-f FILE]         # decrypt to a plaintext file on disk (debug only)
```

The sealed file for `FILE` is `FILE.enc.env` (default `FILE` is `.env.local`).

### Typical workflow

```sh
# one-time, on each machine
envsec init

# fetch/refresh secrets from wherever the "source of truth" lives,
# then seal the result (commit the .enc.env file)
envsec seal -- ./scripts/pull-secrets.sh

# use the secrets without ever writing them to disk
envsec run -- npm run dev

# quick manual edits
envsec edit
```

`seal` decrypts the current sealed file to a plaintext `.env.local` *before* running the pull script, so partial pull scripts can read the existing values (e.g. to only fill missing keys). The plaintext is removed on success, error, or Ctrl-C.

## Security properties

- `run` decrypts **in memory** and `exec(3)`s the command — secrets never touch disk.
- `seal`/`edit`/`export` write plaintext with mode `0600` and remove it on exit.
- Sealed output is written **atomically** (temp file + rename), so a crash can't corrupt the file.
- Re-sealing and editing **preserve all existing recipients** instead of silently re-encrypting to the current machine's key only — a deliberate fix over the original shell script, which could lock out other machines.

## Requirements

- Go 1.27+ to build; the binary itself has no runtime dependencies.
- An age key (run `envsec init`). Key location: `$SOPS_AGE_KEY_FILE` or `~/.config/sops/age/keys.txt`.

## Layout

| File | Purpose |
|---|---|
| `main.go` | CLI dispatch + usage |
| `keys.go` | key file location, generation, public key derivation |
| `crypto.go` | sops library wiring (encrypt/decrypt), quote normalization, atomic writes |
| `flags.go` | `[-f FILE] -- CMD` parsing |
| `cmd_*.go` | one file per subcommand |
| `main_test.go` | unit + end-to-end tests (round trip, seal, edit, export, env injection) |

## Notes

- Only native age identities are supported in `keys.txt` (the format `envsec init` and `age-keygen` write).
- The sops envelope format is identical to `sops encrypt --input-type dotenv --output-type dotenv` output, so files interoperate with the sops CLI.
- Two direct dependencies (`sops` v3, `age`) at their latest versions; everything else is stdlib.