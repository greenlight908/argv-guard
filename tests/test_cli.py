"""Tests for the command-line entry point, and especially its blindness guard.

The exit codes are the contract pre-commit reads: 0 clean, 1 findings, 2 the scan could
not be trusted. The last is the one that matters -- "I could not look" must never be
reported as "I looked and it is fine".
"""

from __future__ import annotations

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
