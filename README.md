# argv-guard

A pre-commit hook that fails if a **secret-shaped variable reaches a spawned process's
argv** in a shell script.

A command line is world-readable from `/proc/<pid>/cmdline` for the life of the process,
so any local user can read a credential passed as an argument:

```bash
curl -sS "https://api.example.com/bot$BOT_TOKEN/send"   # argv: bot<TOKEN>/send  ❌
```

The fix is to pass it on **stdin** instead:

```bash
printf 'url = "%s"\n' "https://api.example.com/bot$BOT_TOKEN/send" \
  | curl -sS --config -                                 # argv: curl -sS --config -  ✅
```

## Usage

```yaml
repos:
  - repo: https://github.com/greenlight908/argv-guard
    rev: v0.2.0
    hooks:
      - id: check-no-secrets-in-argv
```

Or by hand — paths may be files or directories to sweep:

```bash
check-no-secrets-in-argv src/ scripts/
```

## What it matches

A line that BOTH spawns a process (`curl`, `ssh`, `wget`, `psql`, …) AND expands a
variable whose name reads as a credential (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`,
`*API_KEY*`, `*PASSWD*`, `*CREDENTIAL*`).

Anchoring on the *variable name* is a compromise, and worth being honest about: the true
shape is data flow from a secret source into argv, which needs analysis a pre-commit hook
has no business doing. The naming convention is the only static signal available, so this
fails loud and makes every exception explicit rather than trying to be clever and quietly
missing cases.

Crucially it judges **each pipeline stage separately**, so the sanctioned fix above stays
green: the `printf` stage has a secret but spawns nothing, and the `curl` stage spawns but
has no secret. A scanner without that distinction flags the remedy as the bug.

## Waiving a line

Append a reason:

```bash
ssh "$HOST" "mkdir -p $SECRETS_PATH"   # argv-secret-ok: a directory path, not a credential
```

A reason is **required** — a bare pragma tells the next reader nothing about whether it is
still true. The waiver must be a real trailing comment, so quoting the pragma text inside
an argument does not silence a genuine leak beside it.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean — the scanned scripts pass |
| `1`  | Findings — at least one secret reaches argv |
| `2`  | The scan could not be trusted (no paths given, a directory yielded no shell scripts, or a file could not be read) |

The failure header reports a census (`N in M shell script(s) swept`) only for a directory
sweep, which genuinely is one. Given an explicit file list it says `N in the file(s)
checked` instead — pre-commit splits staged files across several invocations, so a
scan-wide count printed from one of them would describe that batch rather than the tree.

Code `2` exists because *"I could not look"* must never be reported as *"I looked and it
is fine"*. A directory sweep that finds nothing to scan is blindness; an explicit file
list that contains no shell is the ordinary case and exits `0`.

## Known limits

Stated rather than implied, because a guard that silently covers half its category is
worse than none — its green is trusted.

- **Shell only.** Python `subprocess` call sites are the identical hazard and are **not**
  covered; catching those needs AST work over f-strings and call sites.
- **Backslash continuations only.** A command held open across lines by an unterminated
  quote or `$(` is not joined, so a secret split that way is missed. Closing this was
  attempted and made the scanner worse on real code — it needs a real shell parser, and
  approximating it badly traded a rare false negative for a false positive.

Both are pinned by tests, so the gaps stay visible rather than being discovered.

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run pyright
```

## License

MIT
