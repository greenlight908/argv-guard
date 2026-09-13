"""Detect secret-bearing variables that reach a spawned process's ARGV, in shell scripts.

A command line is world-readable from `/proc/<pid>/cmdline` for the life of the process,
so any local user can read a credential passed as an argument. The rule this enforces is
simply: **a secret reaches a subprocess on STDIN, never as an argument.**

Prose does not hold that rule on its own. The bug that motivated this scanner was a
notification script that interpolated a bot token into a `curl` URL and rang that way
every six hours; the same shape then shipped twice more in a single pull request and was
caught by a human reviewer rather than by anything structural.

MEASURED, not assumed (`--config -` is the fix this pushes you toward):

    curl ... "https://api.example.com/bot$TOK/send"        -> argv: bot<TOKEN>/send
    printf 'url = "%s"' "...$TOK..." | curl ... --config -  -> argv: curl -sS --config -

WHAT IT MATCHES, AND WHY THAT SHAPE
-----------------------------------
A line that BOTH spawns a process (`curl`, `ssh`, `wget`, `psql`, ...) AND expands a
variable whose name reads as a credential (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, ...).

Anchoring on the *variable name* is a compromise and worth being honest about: the better
rule is to match the shape, not the name, and the true shape here is data flow from a
secret source into argv -- which needs analysis a pre-commit hook has no business doing.
The naming convention is the only static signal, so this fails LOUD and makes every
exception explicit, rather than trying to be clever and quietly missing cases.

SCOPE -- deliberately SHELL ONLY, and this is a KNOWN GAP, not a claim of completeness.
Python clients spawn subprocesses too, and a secret in a `subprocess.run([...])` element is
the identical hazard; catching that needs AST work over f-strings and call sites. A guard
that silently covered half its category would be a false green, so the gap is stated here
and in the failure output -- never implied to be handled.

KNOWN LIMIT -- a multi-line command held open by a QUOTE or `$(` rather than a backslash is
not joined, so a secret split across such lines is missed. This is a heuristic, not a shell
parser, and the boundary is deliberate: joining on unterminated constructs was tried and
made the scanner worse on real code (`http_code="$(` opens a quote, after which a walker
with no `$( ... )` requoting reads the pipeline's `|` as quoted data, stops splitting
stages, and reports a CORRECTLY-WRITTEN script as a leak). A rare false negative beats a
false positive, because a check that cries wolf gets deleted. Pinned by a test so the gap
stays visible.

WAIVING: append `# argv-secret-ok: <reason>` to the line. A reason is required, because a
bare pragma tells the next reader nothing about whether it is still true.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

# Commands that put their arguments in a NEW process's argv. `printf`/`echo` are absent on
# purpose: they are shell builtins, fork nothing, and are precisely the safe way to hand a
# secret to `curl --config -`. Adding them would flag the fix as the bug.
SPAWNERS = (
    "aws",
    "az",
    "curl",
    "docker",
    "gcloud",
    "gh",
    "git",
    "httpie",
    "kubectl",
    "mongosh",
    "mysql",
    "op",
    "psql",
    "redis-cli",
    "rsync",
    "scp",
    "ssh",
    "wget",
)

# An optional path prefix is part of the command, not a reason to miss it: `/usr/bin/curl`
# spawns exactly the same process as `curl`. Note `http`/`https` must NOT appear in
# SPAWNERS: as bare words they match every line containing a URL, which is both a
# false-positive engine and a way to fake a passing test (a test meant to cover
# path-qualified spawners once passed because `https` matched the URL in its sample line
# rather than the command under test).
_SPAWNER_RE = re.compile(rf"""(?:^|[|;&("']|\s)(?:[\w.~-]*/)*({"|".join(SPAWNERS)})\b""")

# A credential-shaped variable expansion: $TOKEN, ${API_KEY}, ${BOT_TOKEN:-}, $password.
#
# `PASS`/`KEY` alone match far too much ordinary prose and code (`PASSED`, `KEYS`,
# `KEYBOARD`), so this list is deliberately the specific ones. A name this misses is a
# naming problem worth fixing at the source rather than a reason to widen the net until
# the scanner cries wolf and gets deleted.
_SECRET_WORDS = (
    "API_KEY",
    "APIKEY",
    "CREDENTIAL",
    "PASSWD",
    "PASSWORD",
    "SECRET",
    "TOKEN",
)
_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")

WAIVER_RE = re.compile(r"#\s*argv-secret-ok:\s*\S")

# A cap on how many physical lines one logical line may absorb. An UNBALANCED quote (a
# stray apostrophe in a `$'...'`, say) otherwise makes every following line look like part
# of the same command, collapsing a whole file into one blob and losing the per-segment
# precision this depends on. Failing back to line-at-a-time after this is the lesser
# error: it can miss a pathological 40-line command, but it cannot go blind file-wide.
_MAX_JOIN = 40

# Directories that are never the subject of a scan: caches, vendored code, virtualenvs.
# Named directories ONLY -- linked git worktrees are pruned separately and structurally,
# by `is_nested_checkout`, because they are named after their branch and no name list can
# anticipate them.
DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "node_modules",
        "site-packages",
        "venv",
    }
)


def is_secret_name(name: str) -> bool:
    """Does this variable name read as a credential?"""
    upper = name.upper()
    return any(word in upper for word in _SECRET_WORDS)


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash-continued lines into (first_line_number, joined_text).

    THE SCANNER MISSED ITS OWN MOTIVATING BUG WITHOUT THIS. The script that prompted it
    spreads one `curl` across a dozen continued lines, with `curl` on the first and
    `${BOT_TOKEN}` on the last, so a line-at-a-time scan saw a spawner with no secret and a
    secret with no spawner, and reported the file clean. A guard that has quietly stopped
    guarding very nearly shipped inside the guard written to prevent one.
    """
    joined: list[tuple[int, str]] = []
    buffer, start, held = "", 0, 0
    for number, raw in enumerate(text.splitlines(), 1):
        if not buffer:
            start = number
        stripped = raw.rstrip()
        # bash does NOT continue a comment. Joining one swallows the following line into a
        # logical line that comment-stripping then discards wholesale, hiding any leak on
        # it -- a real script was found to be exactly this shape.
        in_comment = (buffer + raw).lstrip().startswith("#")
        # An ODD number of trailing backslashes continues the line; an even number ends in
        # a literal backslash and does not. Joining on `\\` would merge two independent
        # commands into one logical line.
        backslash = (len(stripped) - len(stripped.rstrip("\\"))) % 2 == 1
        # DELIBERATELY backslash-only -- see the module docstring's KNOWN LIMIT.
        if backslash and not in_comment and held < _MAX_JOIN:
            buffer += stripped[:-1] + " "
            held += 1
            continue
        joined.append((start, buffer + raw))
        buffer, held = "", 0
    if buffer:
        joined.append((start, buffer))
    return joined


def walk(text: str):
    """Yield (index, char, is_data) over a shell line, tracking quotes and escapes.

    `is_data` is True when the character is INSIDE quotes or was escaped by a preceding
    backslash -- i.e. it is a literal, not shell syntax. One walker for both scanners
    below, because they were drifting apart: comment-stripping and pipeline-splitting each
    had their own quote tracker, and each missed escapes independently.

    Escapes matter for a security check, not just tidiness. `curl https://x/\\|$TOKEN`
    passes a LITERAL pipe to curl, so the token really is in its argv -- but a splitter
    that treats `\\|` as a boundary cuts there, sees a spawner with no secret and a secret
    with no spawner, and reports clean. A guard that can be silenced by a backslash is
    worse than none, because its green is trusted.

    Backslash is not special inside single quotes, which is why the escape branch checks
    the active quote character.
    """
    yield from _walk_state(text)[0]


def _walk_state(text: str, quote: str = "", depth: int = 0):
    """(events, trailing_quote, trailing_paren_depth) -- the state a line ENDS in."""
    events = []
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            events.append((index, char, True))
            continue
        if char == "\\" and quote != "'":
            escaped = True
            events.append((index, char, True))
            continue
        if quote:
            if char == quote:
                quote = ""
            events.append((index, char, True))
            continue
        if char in "\"'":
            quote = char
            events.append((index, char, True))
            continue
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        events.append((index, char, False))
    return events, quote, depth


def strip_comment(line: str) -> str:
    """Drop a trailing `# comment`, ignoring a `#` that sits inside quotes.

    Splitting on the first `#` was a FALSE NEGATIVE:
    `curl -H "Authorization: #$API_TOKEN" ...` had everything from the `#` onward
    discarded, so the secret simply vanished from the scan and the file read clean. A
    guard that reports success because it stopped looking is the exact defect this is for.
    """
    for index, char, active in walk(line):
        if char != "#" or active:
            continue
        # A `#` only opens a comment at the START OF A WORD. Mid-word it is a literal
        # character, so `curl https://x/#$API_TOKEN` really does put the token in argv --
        # and cutting there reported that leak as clean.
        if index == 0 or line[index - 1] in " \t":
            return line[:index]
    return line


# Command separators, not just pipes. `;` and `&&` end a command as surely as `|` does, and
# without them a later builtin's secret is blamed on an earlier spawner -- `curl x; printf
# "$TOK"` was rejected though nothing leaks. Splitting on the raw characters covers `&&`
# and `||` too; `2>&1` also splits, harmlessly, since neither half gains a spawner or
# loses a secret.
_SEPARATORS = "|;&"


def pipe_segments(code: str) -> list[str]:
    """Split a logical line on unquoted command separators, judging each stage alone.

    THIS IS THE WHOLE PRECISION OF THE SCANNER, and without it the check flags the FIX as
    the bug. The sanctioned pattern is

        printf 'header = "Authorization: Bearer %s"\\n' "$token" | curl --config -

    where the secret is an argument to a shell BUILTIN and only the config text crosses the
    pipe. Judged as one blob that reads as "a line with curl and $token on it" -- which is
    precisely what the real defect looks like too. Per segment the difference is structural
    and obvious: the `printf` stage has a secret but spawns nothing, the `curl` stage
    spawns but has no secret. Correctly-written scripts were the first thing this accused.
    """
    segments, current = [], ""
    for _index, char, active in walk(code):
        if char in _SEPARATORS and not active:
            segments.append(current)
            current = ""
        else:
            current += char
    segments.append(current)
    return segments


def offending_vars(line: str) -> list[str]:
    """Credential-shaped variables in the argv of a process-spawning pipeline stage."""
    # The waiver must be a REAL trailing comment, so it is looked for in the tail that
    # comment-stripping removes -- not anywhere on the raw line. Otherwise merely quoting
    # the pragma text (documentation does exactly that) silences a genuine leak beside it.
    code = strip_comment(line)
    if WAIVER_RE.search(line[len(code) :]):
        return []
    if not code:
        return []
    found: set[str] = set()
    for segment in pipe_segments(code):
        if not _SPAWNER_RE.search(segment):
            continue
        found.update(n for n in _VAR_RE.findall(segment) if is_secret_name(n))
    return sorted(found)


def is_shell_file(path: Path) -> bool:
    """A `.sh`/`.bash` suffix, an embedded `.sh.`, or a shell shebang.

    A file we CANNOT READ counts as shell, deliberately. Returning False there was the
    nastiest of this family of bugs: an unreadable extensionless script was classified
    "not shell" and dropped from the scan set before `scan()` ever saw it, so it could
    not even be reported as unreadable -- it simply vanished, and the sweep called the
    tree clean. Including it hands the problem to `scan()`, which records it in
    `unreadable` and forces a non-clean verdict.

    Erring toward INCLUSION is the right direction for a security check: the cost of a
    wrongly-included file is one entry saying it could not be read, while the cost of a
    wrongly-excluded one is a credential nobody ever looked for.
    """
    if path.suffix in {".sh", ".bash"} or ".sh." in path.name:
        return True
    try:
        with path.open("rb") as handle:
            first = handle.readline(200).decode("utf-8", "replace")
    except OSError:
        return True
    return first.startswith("#!") and ("sh" in first or "bash" in first)


def is_nested_checkout(directory: Path) -> bool:
    """Is this directory the root of a DIFFERENT checkout than the one being walked?

    Anchored on the structural form, not on a name. A linked git worktree holds `.git` as
    a FILE (a pointer); an ordinary nested clone holds it as a DIRECTORY. Either way the
    subtree belongs to another checkout and is not this sweep's subject.

    This matters more than it sounds. Worktrees are full copies of the tree, so walking
    them turns ONE finding into one-per-worktree at STALE line numbers: a real sweep of a
    repo with five worktrees reported 51 findings where there were 8, and the duplicates
    pointed at lines that no longer existed. A name-based skip list cannot catch this,
    because a worktree is named after its branch and could be called anything.
    """
    return (directory / ".git").exists()


def shell_files(roots: Iterable[Path], skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS) -> list[Path]:
    """Shell scripts under `roots`. A root may be a directory to walk or a file to take.

    Callers that have a better enumeration than a filesystem walk -- `git ls-files`, say --
    should pass the files directly. A walk cannot tell a tracked file from a build
    artefact, and `skip_dirs` is only a blunt approximation of that distinction.
    """
    found: list[Path] = []
    for root in roots:
        if root.is_file():
            if is_shell_file(root):
                found.append(root)
            continue
        if not root.is_dir():
            continue
        for directory, subdirs, filenames in os.walk(root):
            here = Path(directory)
            # Prune IN PLACE, so a skipped subtree is never descended into at all.
            subdirs[:] = sorted(name for name in subdirs if name not in skip_dirs and not is_nested_checkout(here / name))
            found.extend(path for name in sorted(filenames) if (path := here / name).is_file() and is_shell_file(path))
    return found


class Finding:
    """One credential-shaped variable reaching argv, at a specific line."""

    __slots__ = ("line", "path", "var")

    def __init__(self, path: Path, line: int, var: str) -> None:
        self.path = path
        self.line = line
        self.var = var

    def __repr__(self) -> str:
        return f"Finding({self.path!s}:{self.line}, ${self.var})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return (self.path, self.line, self.var) == (other.path, other.line, other.var)

    def message(self) -> str:
        return (
            f"{self.path}:{self.line}: ${self.var} reaches a spawned process's argv, "
            f"where /proc/<pid>/cmdline exposes it to every local user.\n"
            f"    Pass it on STDIN instead -- e.g. `curl --config -` with the URL "
            f"on stdin, `ssh host 'cat > f'`, `subprocess.run(input=...)`.\n"
            f"    If this genuinely is not a secret, append "
            f"`# argv-secret-ok: <reason>` to the line."
        )


def scan_text(text: str, path: Path) -> list[Finding]:
    """Findings in one script's source. The pure core -- no filesystem, no process."""
    return [Finding(path, number, var) for number, line in logical_lines(text) for var in offending_vars(line)]


class ScanResult(NamedTuple):
    """What a scan found, AND what it could not look at.

    The second half is the point. An earlier version returned bare findings and swallowed
    per-file `OSError`s, so a script that could not be read was indistinguishable from a
    clean one -- it still counted toward "N scripts scanned" while never being examined,
    and a caller could report the whole sweep clean on the strength of it. "I could not
    look" must never reach the caller as "I looked and it is fine", so unreadable paths
    are RETURNED and the caller is forced to decide what they mean.
    """

    findings: list[Finding]
    unreadable: list[tuple[Path, str]]

    @property
    def trustworthy(self) -> bool:
        """True when every requested path was actually read."""
        return not self.unreadable


def scan(paths: Iterable[Path]) -> ScanResult:
    """Findings across already-enumerated shell scripts, plus what could not be read."""
    findings: list[Finding] = []
    unreadable: list[tuple[Path, str]] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            unreadable.append((path, exc.strerror or str(exc)))
            continue
        findings.extend(scan_text(text, path))
    return ScanResult(findings, unreadable)
