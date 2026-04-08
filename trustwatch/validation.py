"""
validation.py — input validation for all public-facing functions.

All validation raises ValidationError with a clear message.
Nothing reaches the network without passing through here first.
"""

from __future__ import annotations

import re
from typing import Optional

from .exceptions import ValidationError

# Package name rules per ecosystem
_NPM_NAME_RE   = re.compile(r"^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$")
_PYPI_NAME_RE  = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
_GITHUB_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

VALID_ECOSYSTEMS = frozenset({"npm", "pypi", "github"})
VALID_FORMATS    = frozenset({"terminal", "json", "sarif", "gha", "markdown"})
VALID_SORT_BY    = frozenset({"score", "name", "ecosystem"})

MAX_PACKAGE_NAME_LEN = 214   # npm limit
MIN_DAYS = 1
MAX_DAYS = 3650              # 10 years


def validate_package_name(name: str, ecosystem: str) -> str:
    """
    Validate and normalise a package name for a given ecosystem.

    Returns:
        Normalised package name (lowercased for npm/pypi).

    Raises:
        ValidationError: If the name is invalid.
    """
    if not name or not name.strip():
        raise ValidationError("package", name, "cannot be empty")

    name = name.strip()

    if len(name) > MAX_PACKAGE_NAME_LEN:
        raise ValidationError(
            "package", name[:40] + "…",
            f"exceeds maximum length of {MAX_PACKAGE_NAME_LEN}"
        )

    if ecosystem == "npm":
        normalised = name.lower()
        if not _NPM_NAME_RE.match(normalised):
            raise ValidationError(
                "package", name,
                "invalid npm package name — use lowercase letters, numbers, hyphens"
            )
        return normalised

    elif ecosystem == "pypi":
        # PyPI normalises hyphens and underscores
        normalised = name.lower().replace("_", "-")
        if not _PYPI_NAME_RE.match(name):
            raise ValidationError(
                "package", name,
                "invalid PyPI package name"
            )
        return normalised

    elif ecosystem == "github":
        if not _GITHUB_SLUG_RE.match(name):
            raise ValidationError(
                "package", name,
                "GitHub packages must be 'owner/repo' format"
            )
        return name

    else:
        raise ValidationError("ecosystem", ecosystem,
                               f"must be one of: {', '.join(sorted(VALID_ECOSYSTEMS))}")


def validate_ecosystem(ecosystem: str) -> str:
    """
    Validate ecosystem string.

    Returns:
        Lowercased ecosystem string.

    Raises:
        ValidationError: If ecosystem is not supported.
    """
    eco = ecosystem.strip().lower()
    if eco not in VALID_ECOSYSTEMS:
        raise ValidationError(
            "ecosystem", ecosystem,
            f"must be one of: {', '.join(sorted(VALID_ECOSYSTEMS))}"
        )
    return eco


def validate_days(days: int) -> int:
    """
    Validate the activity window in days.

    Raises:
        ValidationError: If days is out of range.
    """
    if not isinstance(days, int):
        raise ValidationError("days", days, "must be an integer")
    if days < MIN_DAYS or days > MAX_DAYS:
        raise ValidationError(
            "days", days,
            f"must be between {MIN_DAYS} and {MAX_DAYS}"
        )
    return days


def validate_threshold(threshold: int) -> int:
    """
    Validate a score threshold for CI gate.

    Raises:
        ValidationError: If threshold is out of range.
    """
    if not isinstance(threshold, int):
        raise ValidationError("threshold", threshold, "must be an integer")
    if threshold < 0 or threshold > 100:
        raise ValidationError("threshold", threshold, "must be between 0 and 100")
    return threshold


def validate_output_format(fmt: str) -> str:
    """
    Validate output format string.

    Raises:
        ValidationError: If format is not supported.
    """
    fmt = fmt.strip().lower()
    if fmt not in VALID_FORMATS:
        raise ValidationError(
            "format", fmt,
            f"must be one of: {', '.join(sorted(VALID_FORMATS))}"
        )
    return fmt


def validate_webhook_url(url: Optional[str]) -> Optional[str]:
    """
    Validate webhook URL if provided.

    Raises:
        ValidationError: If URL is provided but malformed.
    """
    if url is None:
        return None
    url = url.strip()
    if not url.startswith(("https://", "http://")):
        raise ValidationError(
            "webhook", url,
            "must start with https:// or http://"
        )
    return url
