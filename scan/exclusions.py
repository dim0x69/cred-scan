"""Load scan exclusions and match credential values."""

from __future__ import annotations

import re
from pathlib import Path

from scan.models import ExclusionFiles, ExclusionPolicy


def _read_patterns(path: Path) -> list[tuple[int, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError(f"could not read exclusion file {path}: {error}") from error
    return [
        (line_number, line)
        for line_number, line in enumerate(lines, 1)
        if line.strip() and not line.lstrip().startswith("#")
    ]


def load_exclusions(files: ExclusionFiles) -> ExclusionPolicy:
    path_patterns = _read_patterns(files.paths)
    credential_patterns = _read_patterns(files.credentials)
    for line_number, pattern in credential_patterns:
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(
                f"invalid credential exclusion at {files.credentials}:{line_number}: {error}"
            ) from error
    return ExclusionPolicy(
        path_file=files.paths,
        path_patterns=tuple(pattern for _, pattern in path_patterns),
        credential_patterns=tuple(pattern for _, pattern in credential_patterns),
    )


def match_credential_exclusion(
    policy: ExclusionPolicy, credential: str
) -> tuple[str, ...] | None:
    matches = tuple(
        pattern
        for pattern in policy.credential_patterns
        if re.search(pattern, credential) is not None
    )
    if not matches:
        return None
    return matches
