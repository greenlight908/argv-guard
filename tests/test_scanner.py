"""Tests for the argv-secret scanner.

Its whole value is telling the DEFECT (`curl "...$TOKEN..."`) apart from the FIX
(`printf ... "$TOKEN" | curl --config -`). Both contain a spawner and a secret-shaped
variable on one line, so every test here pins that distinction rather than the wording of
a message -- and each real-world shape that fooled an earlier draft has a case of its own.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from argv_guard import scanner as guard


class TestSecretNames:
    @pytest.mark.parametrize("name", ["TOKEN", "BOT_TOKEN", "api_key", "MY_SECRET", "DB_PASSWORD", "PASSWD"])
    def test_credential_shaped_names(self, name: str):
        assert guard.is_secret_name(name) is True

    @pytest.mark.parametrize("name", ["HOME", "URL", "MESSAGE", "CHAT_ID", "SILENT"])
    def test_ordinary_names(self, name: str):
        assert guard.is_secret_name(name) is False

    def test_passed_is_not_a_password(self):
        """`PASS`/`KEY` as substrings would match PASSED, KEYS, KEYBOARD -- a check that
        cries wolf gets deleted, so the word list is deliberately specific."""
        assert guard.is_secret_name("TESTS_PASSED") is False
        assert guard.is_secret_name("KEYBOARD_LAYOUT") is False


class TestTheDefect:
    def test_token_in_a_curl_url(self):
        line = 'curl -sS "https://api.example.com/bot${BOT_TOKEN}/sendMessage"'
        assert guard.offending_vars(line) == ["BOT_TOKEN"]

    def test_bearer_header_as_an_argument(self):
        line = 'curl -H "Authorization: Bearer $API_TOKEN" https://example.com'
        assert guard.offending_vars(line) == ["API_TOKEN"]

    def test_secret_in_an_ssh_command(self):
        assert guard.offending_vars('ssh host "deploy --key $DEPLOY_SECRET"') == ["DEPLOY_SECRET"]


class TestTheFixIsNotFlagged:
    """The sanctioned stdin pattern must stay green, or the check punishes the remedy."""

    def test_config_on_stdin_via_printf(self):
        line = 'printf \'url = "%s"\\n\' "https://api.example.com/bot${BOT_TOKEN}/x" | curl --config -'
        assert guard.offending_vars(line) == []

    def test_scope_check_shape(self):
        """A real three-line shape from a credential scope-check -- the first thing an
        earlier draft accused, while it was already correct."""
        line = 'printf \'header = "Authorization: Bearer %s"\\nurl = "%s"\\nsilent\\n\' "$token" "$1" | curl --config -'
        assert guard.offending_vars(line) == []

    def test_a_spawnerless_line_is_ignored(self):
        assert guard.offending_vars('MESSAGE="value ${BOT_TOKEN}"') == []

    def test_a_spawner_without_a_secret_is_ignored(self):
        assert guard.offending_vars('curl -sS "https://example.com/${PATH_PART}"') == []


class TestLineContinuations:
    """The scanner MISSED ITS OWN MOTIVATING BUG before this: the script that prompted it
    spreads one curl over a dozen continued lines, `curl` first and `${BOT_TOKEN}` last."""

    def test_continued_curl_is_joined(self):
        text = 'http_code="$(\n  curl -sS -o /dev/null \\\n    --max-time 10 \\\n    "https://api.example.com/bot${BOT_TOKEN}/sendMessage"\n)"\n'
        joined = guard.logical_lines(text)
        hits = [(n, guard.offending_vars(line)) for n, line in joined]
        assert any(vars_ == ["BOT_TOKEN"] for _, vars_ in hits)

    def test_continuation_reports_the_start_line(self):
        text = 'curl \\\n  -H "Bearer $TOKEN" \\\n  https://x\n'
        joined = guard.logical_lines(text)
        assert joined[0][0] == 1
        assert guard.offending_vars(joined[0][1]) == ["TOKEN"]

    def test_a_continued_pipe_still_separates_stages(self):
        text = 'printf "%s" \\\n  "$TOKEN" | \\\n  curl --config -\n'
        joined = guard.logical_lines(text)
        assert all(guard.offending_vars(line) == [] for _, line in joined)


class TestPrecisionHolesFoundInReview:
    """Three shapes the first draft got wrong. Two were FALSE NEGATIVES -- a guard
    reporting clean on a real leak -- which is the failure this exists to end."""

    def test_a_hash_inside_quotes_is_not_a_comment(self):
        """Splitting on the first `#` treated the rest of the line as a comment, so a
        secret after a `#` inside a quoted argument vanished from the scan."""
        line = 'curl -H "Authorization: #$API_TOKEN" https://example.com'
        assert guard.offending_vars(line) == ["API_TOKEN"]

    @pytest.mark.parametrize("invocation", ["/usr/bin/curl", "/bin/ssh", "./curl", "../tools/curl"])
    def test_path_qualified_spawners_are_recognised(self, invocation: str):
        """`/usr/bin/curl` spawns exactly the same process as `curl`.

        NO URL ON THE LINE, deliberately. The first version of this test ended in
        `https://example.com` and passed against code that could not see `/usr/bin/curl`
        at all -- `https` was in SPAWNERS and matched the URL. The test was green, the
        scanner was blind, and only checking WHY it passed found it. That is why
        `http`/`https` are not spawner words.
        """
        line = f'{invocation} -H "Bearer $API_TOKEN" example.com'
        assert guard.offending_vars(line) == ["API_TOKEN"]

    def test_a_bare_url_is_not_a_spawner(self):
        """The control for the above: a URL alone must not make a line look like a
        command, or every line mentioning https becomes a finding."""
        assert guard.offending_vars('MSG="see https://example.com/$API_TOKEN"') == []

    def test_a_semicolon_ends_the_command(self):
        """`;` and `&&` separate commands as surely as `|`; without them a later builtin's
        secret is attributed to an earlier spawner and the check cries wolf."""
        line = 'curl https://example.com; printf "%s" "$API_TOKEN"'
        assert guard.offending_vars(line) == []

    def test_and_and_also_separates(self):
        line = 'curl https://example.com && printf "%s" "$API_TOKEN"'
        assert guard.offending_vars(line) == []

    def test_separators_do_not_hide_a_real_leak(self):
        """The control for the two above: splitting more must not lose a true positive."""
        line = 'echo start; curl -H "Bearer $API_TOKEN" https://example.com'
        assert guard.offending_vars(line) == ["API_TOKEN"]


class TestShellEscaping:
    """A backslash-escaped character is DATA, not syntax. Missing that turns the splitter
    into a way to hide a leak from the very check meant to find it."""

    def test_an_escaped_pipe_is_not_a_command_boundary(self):
        r"""`\|` is a literal pipe passed to curl, so the token is still in its argv --
        but an unescaped-aware splitter cut there, leaving a spawner with no secret and a
        secret with no spawner, and called it clean."""
        assert guard.offending_vars(r"curl https://example.com/\|$API_TOKEN") == ["API_TOKEN"]

    def test_an_escaped_semicolon_is_not_a_boundary(self):
        assert guard.offending_vars(r"curl https://x/\;$API_TOKEN") == ["API_TOKEN"]

    def test_an_escaped_quote_does_not_flip_quote_state(self):
        r"""`\"` inside a quoted string must not close it -- otherwise every separator
        after it is mis-tracked and the rest of the line is judged in the wrong state."""
        line = r'curl -H "he said \"hello\"" -d "$API_TOKEN" example.com'
        assert guard.offending_vars(line) == ["API_TOKEN"]

    def test_an_escaped_hash_is_not_a_comment(self):
        assert guard.offending_vars(r"curl example.com/\#x -d $API_TOKEN") == ["API_TOKEN"]


class TestCommentPosition:
    """In bash a `#` only starts a comment at the START OF A WORD. Mid-word it is a
    literal character, so treating every unquoted `#` as a comment discarded real argv --
    another false negative on a live credential."""

    def test_a_hash_mid_word_is_literal_not_a_comment(self):
        assert guard.offending_vars("curl https://example.com/#$API_TOKEN") == ["API_TOKEN"]

    def test_a_fragment_before_the_secret_still_leaks(self):
        assert guard.offending_vars("curl https://x/page#frag -d $API_TOKEN") == ["API_TOKEN"]

    def test_a_real_comment_after_whitespace_is_still_stripped(self):
        """The control: genuine trailing comments must keep being ignored, or the check
        starts reporting on prose."""
        assert guard.strip_comment("curl example.com  # note about $TOKEN").rstrip() == ("curl example.com")

    def test_a_whole_line_comment_is_still_a_comment(self):
        assert guard.offending_vars("# curl -d $API_TOKEN example.com") == []


class TestCommentsDoNotContinue:
    """bash does not honour a backslash continuation inside a comment. Joining one
    swallows the NEXT line into a logical line that comment-stripping then discards
    wholesale -- so a real leak on that following line is never seen."""

    def test_a_comment_ending_in_a_backslash_does_not_swallow_the_next_line(self):
        text = '# a trailing backslash \\\ncurl -H "Bearer $API_TOKEN" example.com\n'
        joined = guard.logical_lines(text)
        assert any(guard.offending_vars(line) == ["API_TOKEN"] for _, line in joined)

    def test_a_real_continuation_still_joins(self):
        """The control for the above."""
        text = 'curl \\\n  -H "Bearer $API_TOKEN" example.com\n'
        joined = guard.logical_lines(text)
        assert guard.offending_vars(joined[0][1]) == ["API_TOKEN"]


class TestMoreHolesFromReview:
    """Round four. Every one of these is a FALSE NEGATIVE -- the guard reporting clean on
    a real leak -- which is the only kind that actually matters for a security check."""

    @pytest.mark.parametrize("quote", ['"', "'"])
    def test_a_quoted_command_path_is_still_a_spawner(self, quote: str):
        """`"/usr/bin/curl" -H "Bearer $TOK"` runs curl with the token in argv, but an
        opening quote did not satisfy the regex's prefix, so the line read clean."""
        line = f'{quote}/usr/bin/curl{quote} -H "Bearer $API_TOKEN" example.com'
        assert guard.offending_vars(line) == ["API_TOKEN"]

    def test_a_waiver_inside_a_quoted_argument_does_not_count(self):
        """The pragma must be a real trailing comment. Otherwise echoing the pragma text
        -- as documentation does -- silences a genuine leak on the same line."""
        line = 'curl -d "$API_TOKEN" "# argv-secret-ok: not really a waiver"'
        assert guard.offending_vars(line) == ["API_TOKEN"]

    def test_an_escaped_backslash_does_not_continue_the_line(self):
        r"""A line ending in `\\` ends in a literal backslash and does NOT continue, so
        joining it would merge two independent commands into one logical line.

        Quotes are deliberately BALANCED here. The first version of this fixture ended
        `"a\\`, leaving an open quote -- which the open-construct rule then continued, for
        a completely different and correct reason. The test was measuring the wrong thing.
        """
        text = 'printf "%s" "a"\\\\\ncurl -d $API_TOKEN example.com\n'
        joined = guard.logical_lines(text)
        assert len(joined) == 2


class TestKnownLimit:
    """A multi-line command held open by a quote or `$(` rather than a backslash is NOT
    joined, so a secret split across such lines is missed. This is a DOCUMENTED LIMIT, and
    it is pinned here so the gap is visible rather than discovered.

    Closing it was attempted and made the scanner worse on real code: a real script's own
    `http_code="$(` opens a double quote, and a walker without `$( ... )` requoting then
    reads the pipeline's `|` as quoted data, stops splitting stages, and reports the FIXED
    script as a leak. Doing it properly needs a real shell parser. Approximating it badly
    traded a rare false negative for a false positive on the one file the check exists
    for -- and a check that cries wolf gets deleted.
    """

    def test_a_multiline_command_substitution_is_a_known_miss(self):
        text = 'curl -H "$(\n  printf \'Authorization: Bearer %s\' "$API_TOKEN"\n)" https://example.com\n'
        joined = guard.logical_lines(text)
        assert not any(guard.offending_vars(line) for _, line in joined)

    def test_balanced_lines_are_not_joined(self):
        """The control that matters: ordinary complete commands stay separate, so
        per-segment precision survives."""
        text = 'echo "one"\necho "two"\necho "three"\n'
        assert len(guard.logical_lines(text)) == 3


class TestPipeSegments:
    def test_quoted_pipe_does_not_split(self):
        segments = guard.pipe_segments('curl "a|b" $TOKEN')
        assert len(segments) == 1

    def test_unquoted_pipe_splits(self):
        assert len(guard.pipe_segments("printf x | curl -")) == 2


class TestWaiver:
    def test_a_waiver_with_a_reason_silences_the_line(self):
        line = 'curl "https://x/$TOKEN"  # argv-secret-ok: public repo path, not a credential'
        assert guard.offending_vars(line) == []

    def test_a_bare_pragma_does_not_count(self):
        """A reason is required -- a bare pragma tells the next reader nothing."""
        line = 'curl "https://x/$TOKEN"  # argv-secret-ok:'
        assert guard.offending_vars(line) == ["TOKEN"]


class TestShellFileDiscovery:
    def test_a_suffixed_script_is_shell(self, tmp_path: Path):
        path = tmp_path / "deploy.sh"
        path.write_text("echo hi\n", encoding="utf-8")
        assert guard.is_shell_file(path) is True

    def test_an_embedded_sh_is_shell(self, tmp_path: Path):
        """A `*.sh.tpl` template renders to a deployed script and leaks identically."""
        path = tmp_path / "logger.sh.tpl"
        path.write_text("echo hi\n", encoding="utf-8")
        assert guard.is_shell_file(path) is True

    def test_an_extensionless_shebang_is_shell(self, tmp_path: Path):
        path = tmp_path / "runme"
        path.write_text("#!/bin/bash\necho hi\n", encoding="utf-8")
        assert guard.is_shell_file(path) is True

    def test_a_python_file_is_not_shell(self, tmp_path: Path):
        path = tmp_path / "thing.py"
        path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        assert guard.is_shell_file(path) is False

    def test_a_file_root_is_taken_directly(self, tmp_path: Path):
        path = tmp_path / "a.sh"
        path.write_text("echo hi\n", encoding="utf-8")
        assert guard.shell_files([path]) == [path]

    def test_skip_dirs_are_not_walked(self, tmp_path: Path):
        """A linked git worktree is a full copy of the tree. Walking one turns a single
        finding into one-per-worktree, at STALE line numbers -- which reads as many
        separate defects and buries the real count."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "real.sh").write_text("echo hi\n", encoding="utf-8")
        (tmp_path / "node_modules" / "nested").mkdir(parents=True)
        (tmp_path / "node_modules" / "nested" / "vendored.sh").write_text("echo hi\n", encoding="utf-8")
        found = guard.shell_files([tmp_path])
        assert [p.name for p in found] == ["real.sh"]


class TestScan:
    def test_scan_reports_path_and_line(self, tmp_path: Path):
        path = tmp_path / "leak.sh"
        path.write_text(
            '#!/bin/bash\necho ok\ncurl -H "Bearer $API_TOKEN" example.com\n',
            encoding="utf-8",
        )
        findings = guard.scan([path]).findings
        assert len(findings) == 1
        assert findings[0].line == 3
        assert findings[0].var == "API_TOKEN"
        assert findings[0].path == path

    def test_a_clean_script_yields_nothing(self, tmp_path: Path):
        path = tmp_path / "clean.sh"
        path.write_text(
            '#!/bin/bash\nprintf \'header = "Authorization: Bearer %s"\\n\' "$API_TOKEN" | curl --config -\n',
            encoding="utf-8",
        )
        assert guard.scan([path]).findings == []


class TestNestedCheckoutsArePruned:
    """A linked worktree is a full copy of the tree. Walking one multiplies every finding
    by the number of worktrees, at line numbers that may no longer exist -- which reads as
    many separate defects and buries the true count.

    This is pruned STRUCTURALLY (`.git` present) rather than by name, because a worktree
    is named after its branch and no skip list can anticipate that.
    """

    def test_a_linked_worktree_is_not_walked(self, tmp_path: Path):
        """A worktree's `.git` is a FILE, not a directory."""
        leak = '#!/bin/bash\ncurl -H "Bearer $API_TOKEN" example.com\n'
        (tmp_path / "real.sh").write_text(leak, encoding="utf-8")

        worktree = tmp_path / ".worktrees" / "some-branch"
        worktree.mkdir(parents=True)
        (worktree / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")
        (worktree / "real.sh").write_text(leak, encoding="utf-8")

        found = guard.shell_files([tmp_path])
        assert [p.relative_to(tmp_path).as_posix() for p in found] == ["real.sh"]

    def test_a_nested_clone_is_not_walked(self, tmp_path: Path):
        """An ordinary nested clone holds `.git` as a DIRECTORY -- also another repo."""
        (tmp_path / "real.sh").write_text("#!/bin/bash\necho hi\n", encoding="utf-8")
        nested = tmp_path / "vendor" / "other-repo"
        (nested / ".git").mkdir(parents=True)
        (nested / "theirs.sh").write_text("#!/bin/bash\necho hi\n", encoding="utf-8")

        found = guard.shell_files([tmp_path])
        assert [p.relative_to(tmp_path).as_posix() for p in found] == ["real.sh"]

    def test_the_control_an_ordinary_subdirectory_IS_walked(self, tmp_path: Path):
        """The control that proves the pruning is targeted and not just 'skip subdirs'."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "nested.sh").write_text("#!/bin/bash\necho hi\n", encoding="utf-8")
        found = guard.shell_files([tmp_path])
        assert [p.relative_to(tmp_path).as_posix() for p in found] == ["src/nested.sh"]


class TestAnUnreadableFileIsNotACleanFile:
    """`scan()` used to swallow per-file `OSError` and carry on.

    That made an unreadable script indistinguishable from a clean one: it still counted
    toward "N scripts scanned" while never being examined, so a caller could report a
    whole sweep clean on the strength of a file it had never opened. Raised on review --
    the same false green as the repo-level case, one level further down.
    """

    def test_an_unreadable_file_is_reported_not_skipped(self, tmp_path: Path):
        readable = tmp_path / "fine.sh"
        readable.write_text("#!/bin/bash\necho hi\n", encoding="utf-8")
        missing = tmp_path / "gone.sh"  # never created -- read raises

        result = guard.scan([readable, missing])

        assert result.findings == []
        assert [p for p, _ in result.unreadable] == [missing]
        assert result.trustworthy is False

    def test_a_fully_readable_scan_is_trustworthy(self, tmp_path: Path):
        """The control: without it, a scan that always reported unreadable would pass."""
        path = tmp_path / "fine.sh"
        path.write_text("#!/bin/bash\necho hi\n", encoding="utf-8")

        result = guard.scan([path])

        assert result.unreadable == []
        assert result.trustworthy is True

    def test_findings_survive_alongside_an_unreadable_file(self, tmp_path: Path):
        """A real leak must not be dropped just because a sibling could not be read."""
        leak = tmp_path / "leak.sh"
        leak.write_text('#!/bin/bash\ncurl -H "Bearer $API_TOKEN" example.com\n', encoding="utf-8")

        result = guard.scan([leak, tmp_path / "gone.sh"])

        assert [f.var for f in result.findings] == ["API_TOKEN"]
        assert result.trustworthy is False
