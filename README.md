# pqenvEditor

Post-quantum encrypted `.env` file editor. Your secrets never touch disk in
plaintext — not even temporarily.

```
ML-KEM-768 (FIPS 203)  →  key encapsulation
ChaCha20-Poly1305      →  authenticated encryption of the actual content
```

Both primitives are implemented from scratch (no external crypto library)
and verified against official test vectors — see [Verification](#verification)
below before you trust this with real secrets.

## Why

`.env` files sit on disk in plaintext, readable by any process or AI agent
with filesystem access, and vulnerable to future quantum attacks on
classical key exchange. pqenvEditor encrypts `.env` at rest with a
post-quantum KEM, and gives you a small terminal editor that decrypts into
memory, lets you edit, and re-encrypts on save — plaintext exists only in
process memory, never in a temp file.

Threat model this addresses:
- **Tampering** — without the ML-KEM secret key, a modified ciphertext
  fails AEAD authentication. Decryption is refused, loudly, not silently.
- **Rollback / replay** — a monotonic sequence counter (checked against a
  local sidecar file) detects an attacker replacing the current file with
  an older, still-validly-encrypted version.
- **Plaintext exposure** — the editor never writes decrypted content to
  disk, not even to `/tmp` or `/dev/shm`.

This does **not** protect against a compromised machine where the attacker
already has read access to `~/.atema/pq_secret.key`, and the underlying
lattice arithmetic is not constant-time (see [Limitations](#limitations)).

## Verification

Hand-rolled cryptography is risky, so every primitive was compiled and run
against official published test vectors before anything else was built on
top of it:

| Component | Verified against | Result |
|---|---|---|
| Keccak / SHA3 / SHAKE | NIST known-answer values | exact match |
| **ML-KEM-768** | [C2SP/CCTV](https://github.com/C2SP/CCTV/tree/main/ML-KEM) official accumulated KAT (10,000 keygen/encaps/decaps rounds → SHAKE128 digest) | exact match: `f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3` |
| ChaCha20-Poly1305 | RFC 8439 §2.8.2 official AEAD vector | exact match (ciphertext + tag) |
| Full pipeline | Custom integration tests | encrypt/decrypt round-trip, tamper detection, rollback detection all pass |
| Editor | PTY-driven interactive tests (Python) | create/save/reopen/edit/reject-tampered/reject-rollback all pass |

Note: the ML-KEM-768 implementation matches the FIPS 203 initial public
draft convention (Kyber round-3 compatible, the "Â-fix"), which is what
the CCTV vectors target. If you need byte-for-byte interop with a
different FIPS-203-final library, re-verify against that library's
convention first.

## Build

```sh
git clone https://github.com/zerojat7-ui/pqenvEditor
cd pqenvEditor
sh build.sh
```

No dependencies beyond a C11 compiler and a POSIX environment
(`/dev/urandom`, `termios`). No liboqs, no OpenSSL, nothing to link.

Tests are split into two tiers:

```sh
sh build.sh test-api     # algorithm-level: pure function calls, no filesystem,
                          # checked against official test vectors — safe to run
                          # anywhere, deterministic, good for CI
sh build.sh test-local   # integration: real files/keys/terminal, but fully
                          # sandboxed in a throwaway mkdtemp() directory —
                          # never touches your real ~/.atema/
sh build.sh              # builds + runs both, plus the two programs
```

See [tests/](tests/) for details on what each tier covers.

## Usage

```sh
# one-time: generate your ML-KEM-768 keypair
./pq_env_keygen ~/.atema/pq_secret.key ~/.atema/pq_public.key

# open (or create) an encrypted .env
./pq_env_editor ./.env.kpqe --pub ~/.atema/pq_public.key --sec ~/.atema/pq_secret.key
```

Keys default to `~/.atema/pq_public.key` and `~/.atema/pq_secret.key` if
`--pub`/`--sec` are omitted.

**Editor controls**

| Key | Action |
|---|---|
| Arrows / Home / End / PgUp / PgDn | Move |
| Backspace / Delete / Enter | Edit |
| `Ctrl-S` | Save (re-encrypts with a fresh ML-KEM capsule + nonce) |
| `Ctrl-Q` | Quit (asks again if there are unsaved changes) |
| `Ctrl-X` | Save and quit |

Opening a tampered or rolled-back file is refused before the editor even
starts, with a message explaining which check failed.

## Applying the values to another program

Encrypting `.env` is only half the point — at some point something has to
actually *use* the values. Three ways to do that, depending on what you're
integrating with:

**1. Non-interactive encryption (scripts / migration)**

```sh
cat .env | ./pq_env_encrypt_cli ./app.env.kpqe --pub ~/.atema/pq_public.key
```
Reads plaintext from stdin, encrypts it, writes `.kpqe`. No secret key
needed — encryption only requires the public key. Useful for migrating an
existing plaintext `.env` or scripting from CI.

**2. Run any program with the decrypted values injected (recommended for
most cases — Python, Node, shell scripts, other binaries, anything)**

```sh
./pq_env_exec ./app.env.kpqe --sec ~/.atema/pq_secret.key -- python3 app.py
./pq_env_exec ./app.env.kpqe --sec ~/.atema/pq_secret.key -- node server.js
./pq_env_exec ./app.env.kpqe --sec ~/.atema/pq_secret.key -- ./my_c_program
```
This decrypts in memory, sets the values as real environment variables,
then `execvp()`s the target command — the wrapper process itself is
replaced, so `app.py` just sees a normal `os.environ` / `process.env` /
`getenv()` with your secrets in it. Nothing is ever printed to stdout or
written to disk in plaintext. (Standard caveat that applies to *any* env
injector, including `direnv`/`dotenv-cli`/`aws-vault exec`: another
process running as the same user can still read a running process's
environment via `/proc/<pid>/environ` — that's an OS-level property, not
something this tool can change.)

**Storing multiple services' keys in one `.env`, but scoping what each
program actually receives**

Most real setups don't have one secret — they have an AI key, a DB
password, a payment provider key, etc., all in the same file. Store them
together, but use `--only` to give each program just what it needs
(least privilege — if `ai_worker.py` gets compromised or leaks its own
env somewhere, `STRIPE_KEY` was never in its process to begin with):

```sh
# all.env.kpqe has OPENAI_API_KEY, STRIPE_KEY, DB_PASSWORD, JWT_SECRET...

pq_env_exec ./all.env.kpqe --only OPENAI_API_KEY          -- python3 ai_worker.py
pq_env_exec ./all.env.kpqe --only STRIPE_KEY               -- node payment_service.js
pq_env_exec ./all.env.kpqe --only DB_PASSWORD,JWT_SECRET   -- ./db_migrate
```
Each process's environment contains *only* the key(s) named in `--only`
— the rest of the file's contents were decrypted in memory to check them,
but were never set as environment variables for that child. Omit `--only`
to get the old behavior (everything injected).

**3. Need the values in your own config system, not `os.environ`
(any language — parse it yourself)**

```sh
./pq_env_decrypt_cli ./app.env.kpqe --sec ~/.atema/pq_secret.key
```
Prints the decrypted `KEY=VALUE` lines to stdout, nothing else. Use this
when a language wants to load secrets into its own structured config
(a dict, a JSON object, whatever) instead of relying on inherited process
environment variables. **Pipe it directly into something — never redirect
it to a file** (`> .env` would put plaintext back on disk, exactly what
this tool exists to avoid). This is the same tradeoff every secrets-CLI
has (`sops -d`, `pass show`, `aws secretsmanager get-secret-value`):
stdout is the interop point, so keep it a pipe, not a file.

```sh
# safe: straight into another process, never touches disk
export $(./pq_env_decrypt_cli ./app.env.kpqe --sec SEC | xargs)
docker run --env-file <(./pq_env_decrypt_cli ./app.env.kpqe --sec SEC) myimage

# need just one value out of a multi-key .env? --key does an exact match
# (won't confuse OPENAI_API_KEY with OPENAI_API_KEY_OLD) and prints only
# that value, nothing else:
API_KEY=$(./pq_env_decrypt_cli ./app.env.kpqe --sec SEC --key OPENAI_API_KEY)
```

**4. Link directly into your own C program (tightest option)**

```c
#include "pq_env_loader.h"

int main(void) {
    if (pq_env_load_into_process("./app.env.kpqe",
                                  "~/.atema/pq_public.key",
                                  "~/.atema/pq_secret.key") != 0) {
        fprintf(stderr, "failed to load encrypted .env\n");
        return 1;
    }
    // getenv("OPENAI_API_KEY") now works normally
}
```
Compile `pq_env_loader.c` together with `pq_keccak.c pq_mlkem.c
pq_chacha20poly1305.c pq_env_crypto.c` and your program. The plaintext
never leaves your process's memory at all, not even briefly in a child
process's environment block. For the same scoped-access use case as
`pq_env_exec --only`, call `pq_env_load_into_process_filtered()` instead
with a list of allowed key names.

**Which one, for "any language + high security"?**

| Situation | Use | Why |
|---|---|---|
| Launching a Python/Node/Ruby/Go/anything process | `pq_env_exec` | universal — env vars work in every language, nothing touches disk |
| Need values parsed into your own config object | `pq_env_decrypt_cli`, piped | still no disk, works from any language that can read stdin/a pipe |
| Writing the consuming program in C | `pq_env_loader.h` linked in | plaintext never leaves that one process at all |
| Browser-side JS / HTML | **none of the above** | a browser is untrusted client code — see below |

None of this reaches into a browser tab, and that's intentional, not a
gap: anything shipped to `<script>` is visible to the end user via
view-source or devtools, full stop. If a web page needs a secret-gated
capability, put a small server in the middle (any of the options above)
that holds the secret and exposes only the *result* of using it — the
browser talks to your server, never to the key.

All four paths share the same rollback protection (`<path>.seq` sidecar)
and the same tamper rejection as the editor.

## File format (`.env.kpqe`)

```
magic[4]="KPQE"  version[1]  reserved[3]
mlkem_ct[1088]                       fresh ML-KEM-768 capsule, re-generated every save
seq[8] (big-endian)                  monotonic counter, checked against a local
                                      "<path>.seq" sidecar to detect rollback
file_id[16]                          fixed at file creation
nonce[12]  tag[16]                   ChaCha20-Poly1305
ciphertext[...]                      the actual .env content
```

`magic ‖ … ‖ file_id` (1120 bytes) is authenticated as AEAD associated
data, binding the whole header to the ciphertext.

## Limitations

- The NTT/CBD polynomial arithmetic is **not constant-time**. Scope this
  to local, single-user file encryption where an attacker can't measure
  cycle-accurate timing on the same machine — don't repurpose it for a
  networked key-exchange service as-is.
- No key rotation / multi-recipient support yet — one keypair per machine.
- Decrypted plaintext lives in normal (non-`mlock`'d) heap memory during
  editing; a core dump or swap could theoretically leak it. See the open
  items in the design doc.
- All randomness (keys, seeds, nonces, file IDs) goes through
  `pq_random_bytes()` (`pq_random.c`): `getentropy()` first, a
  timeout-bounded `/dev/urandom` fallback (5s, so a container/embedded
  system with an unseeded entropy pool fails loudly instead of hanging
  forever), and — deliberately — **no fallback to a non-cryptographic
  PRNG under any circumstance**. If both sources are unavailable, key
  generation fails with a clear message instead of silently producing a
  predictable key. If you're deploying somewhere without `/dev/urandom`
  or `getentropy()` at all (unusual, but some minimal embedded targets),
  you'll need to add a platform-specific source to `pq_random.c` yourself
  rather than relying on a weaker default.

## Project layout

```
pq_keccak.h/c               Keccak-f[1600], SHA3-256/512, SHAKE128/256
pq_random.h/c                CSPRNG source (getentropy + timeout-bounded /dev/urandom fallback)
pq_mlkem.h/c                ML-KEM-768 (FIPS 203)
pq_chacha20poly1305.h/c     ChaCha20-Poly1305 AEAD (RFC 8439)
pq_env_crypto.h/c           .kpqe file format, key management, rollback check
pq_env_editor_core.h/c      testable editor core (buffer<->plaintext, open/save)
pq_env_editor.c             terminal UI (raw mode, kilo-style)
pq_env_keygen.c             keypair generation CLI
pq_env_encrypt_cli.c        non-interactive stdin encryption (scripts/migration)
pq_env_loader.h/c           library: apply decrypted values via setenv()
pq_env_exec.c                CLI exec-wrapper: run another program with values injected
pq_env_decrypt_cli.c         stdout decryption for programmatic/any-language parsing
build.sh                    builds + runs everything (see Build)

tests/api/                  algorithm-level tests — pure functions, no filesystem
  test_keccak.c                NIST known-answer values (SHA3/SHAKE)
  test_mlkem.c                 self-consistency (200 keygen/encaps/decaps rounds)
  test_cctv.c                  official C2SP/CCTV accumulated KAT (10,000 rounds)
  test_chacha.c                RFC 8439 §2.8.2 official AEAD vector
  test_env_crypto.c            .kpqe format round-trip, tamper/rollback (in-memory)
  test_random.c                 CSPRNG source (chunking, distinctness, bad-args rejection)

tests/local/                 integration tests — real files/keys/terminal,
                              always sandboxed in a throwaway mkdtemp() dir
  test_editor_core.c           open/save/reopen/re-edit against real files
  test_editor_interactive.py   drives pq_env_editor over a real pty (typing,
                                save, reopen, plus tamper/rollback rejection)
```

## Verification (details)

`test-api` is what you'd point a CI pipeline at — deterministic, no side
effects. `test-local` is closer to "does the actual tool work the way a
person would use it" (it's what caught a real rollback-check off-by-one
during development — see git history) and is slower since it spawns a
real pty per run.

## License

MIT — see [LICENSE](LICENSE).

## Author

zerojat7
