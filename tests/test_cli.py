"""Tests for the command-line entry point, and especially its blindness guard.

The exit codes are the contract pre-commit reads: 0 clean, 1 findings, 2 the scan could
not be trusted. The last is the one that matters -- "I could not look" must never be
reported as "I looked and it is fine".
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from argv_guard.cli import main


def _script(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


class TestExitCodes:
    def test_a_clean_file_exits_zero(self, tmp_path: Path):
        path = _script(tmp_path / "clean.sh", "#!/bin/bash\necho hello\n")
        assert main([str(path)]) == 0

    def test_a_leak_exits_one(self, tmp_path: Path):
        path = _script(
            tmp_path / "leak.sh",
            '#!/bin/bash\ncurl -H "Bearer $API_TOKEN" example.com\n',
        )
        assert main([str(path)]) == 1

    def test_a_clean_directory_sweep_exits_zero(self, tmp_path: Path):
        _script(tmp_path / "clean.sh", "#!/bin/bash\necho hello\n")
        assert main([str(tmp_path)]) == 0

    def test_a_directory_sweep_finds_the_leak(self, tmp_path: Path):
        _script(
            tmp_path / "leak.sh",
            '#!/bin/bash\ncurl -H "Bearer $API_TOKEN" example.com\n',
        )
        assert main([str(tmp_path)]) == 1


class TestBlindnessGuard:
    """Zero subjects is blindness, not health -- but only when a SWEEP was asked for."""

    def test_no_paths_at_all_is_refused(self, capsys: pytest.CaptureFixture[str]):
        """A misconfigured hook that passes nothing must not look like a clean tree."""
        assert main([]) == 2
        assert "refusing to report success" in capsys.readouterr().err

    def test_a_directory_with_no_shell_scripts_is_refused(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """The caller asked for a sweep and got nothing back. That is not a clean sweep --
        it is a sweep that pointed at the wrong place, which is how a guard silently
        stops guarding."""
        (tmp_path / "notes.md").write_text("nothing here\n", encoding="utf-8")
        assert main([str(tmp_path)]) == 2
        assert "found NO shell scripts" in capsys.readouterr().err

    def test_an_explicit_file_list_with_no_shell_is_NOT_refused(self, tmp_path: Path):
        """The counter-case, and the reason the guard is scoped to directories.

        pre-commit passes the files a commit touched. A commit touching no shell at all is
        the ordinary case, not a misconfiguration -- failing it would make the hook
        unusable and get it removed, taking the real coverage with it.
        """
        path = tmp_path / "thing.py"
        path.write_text("print('hi')\n", encoding="utf-8")
        assert main([str(path)]) == 0


class TestOutput:
    def test_a_finding_names_the_variable_and_the_remedy(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        path = _script(
            tmp_path / "leak.sh",
            '#!/bin/bash\ncurl -H "Bearer $API_TOKEN" example.com\n',
        )
        main([str(path)])
        err = capsys.readouterr().err
        assert "$API_TOKEN" in err
        assert "/proc/<pid>/cmdline" in err
        assert "--config -" in err
        assert "argv-secret-ok" in err

    def test_the_shell_only_gap_is_stated_not_implied(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """A guard that silently covers half its category is a false green. The Python
        subprocess gap is real, so it is printed on every failure rather than assumed."""
        path = _script(
            tmp_path / "leak.sh",
            '#!/bin/bash\ncurl -H "Bearer $API_TOKEN" example.com\n',
        )
        main([str(path)])
        assert "SHELL only" in capsys.readouterr().err


class TestTheCountOnlyClaimsWhatItMeasured:
    """pre-commit splits staged files across several invocations, so a scan-wide census
    printed from one of them describes the BATCH, not the tree.

    Found on the first real run: seven batches each announced "1 in 3 shell script(s)
    scanned" for a repo holding 38 of them. A confident number that is really measuring
    the instrument is worse than no number at all.
    """

    def test_a_file_list_does_not_claim_a_census(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        path = _script(
            tmp_path / "leak.sh",
            '#!/bin/bash\ncurl -H "Bearer $API_TOKEN" example.com\n',
        )
        main([str(path)])
        err = capsys.readouterr().err
        assert "the file(s) checked" in err
        assert "swept" not in err

    def test_a_directory_sweep_does_claim_one(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """The counter-case: a sweep really is the census, so it keeps the count."""
        _script(
            tmp_path / "leak.sh",
            '#!/bin/bash\ncurl -H "Bearer $API_TOKEN" example.com\n',
        )
        _script(tmp_path / "clean.sh", "#!/bin/bash\necho hi\n")
        main([str(tmp_path)])
        err = capsys.readouterr().err
        assert "1 in 2 shell script(s) swept" in err


class TestAnUnreadableFileIsUntrusted:
    def test_an_unreadable_file_exits_two_not_zero(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """Exit 0 would tell pre-commit the commit is clean on a file never opened.

        A NON-EXISTENT path is the wrong fixture and the first version used one:
        `shell_files` drops it before the scan, so the test passed for a reason with
        nothing to do with readability. The real shape is a file that EXISTS, is
        recognised as shell by its suffix (so nothing opens it first), and then fails
        to read.
        """
        _script(tmp_path / "fine.sh", "#!/bin/bash\necho hi\n")
        locked = _script(tmp_path / "locked.sh", "#!/bin/bash\necho hi\n")
        locked.chmod(0o000)
        if os.access(locked, os.R_OK):  # running as root: nothing is unreadable
            pytest.skip("cannot make a file unreadable as this user")

        try:
            assert main([str(tmp_path / "fine.sh"), str(locked)]) == 2
            err = capsys.readouterr().err
            assert "could NOT READ" in err
            assert "cannot be reported as clean" in err
        finally:
            locked.chmod(0o644)

    def test_the_control_all_readable_and_clean_exits_zero(self, tmp_path: Path):
        path = _script(tmp_path / "fine.sh", "#!/bin/bash\necho hi\n")
        assert main([str(path)]) == 0
