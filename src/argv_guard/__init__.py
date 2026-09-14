"""Detect secrets reaching a spawned process's argv in shell scripts."""

from __future__ import annotations

__version__ = "0.3.0"

from .scanner import (
    Finding,
    ScanResult,
    is_secret_name,
    is_shell_file,
    logical_lines,
    offending_vars,
    pipe_segments,
    scan,
    scan_text,
    shell_files,
    spawner_wrappers,
    strip_comment,
)

__all__ = [
    "Finding",
    "ScanResult",
    "__version__",
    "is_secret_name",
    "is_shell_file",
    "logical_lines",
    "offending_vars",
    "pipe_segments",
    "scan",
    "scan_text",
    "shell_files",
    "spawner_wrappers",
    "strip_comment",
]
