"""
exceptions.py — typed exceptions for trustwatch.

Using specific exception types means:
  - callers can catch exactly what they expect
  - error messages are consistent
  - unexpected errors still propagate (no silent swallowing)
"""

from __future__ import annotations


class TrustwatchError(Exception):
    """Base for all trustwatch errors."""


class ScanError(TrustwatchError):
    """Raised when a registry API call fails unrecoverably."""

    def __init__(self, package: str, ecosystem: str, reason: str) -> None:
        self.package   = package
        self.ecosystem = ecosystem
        self.reason    = reason
        super().__init__(f"Scan failed for {package} ({ecosystem}): {reason}")


class NetworkError(TrustwatchError):
    """Raised when an HTTP request fails."""

    def __init__(self, url: str, reason: str) -> None:
        self.url    = url
        self.reason = reason
        super().__init__(f"Network error fetching {url}: {reason}")


class RateLimitError(NetworkError):
    """Raised when GitHub rate limit is hit."""

    def __init__(self, url: str) -> None:
        super().__init__(
            url,
            "GitHub rate limit hit (60 req/hr unauthenticated). "
            "Set GITHUB_TOKEN env var or pass --token. "
            "Free token at: https://github.com/settings/tokens",
        )


class NotFoundError(NetworkError):
    """Raised when a package doesn't exist in the registry."""

    def __init__(self, url: str) -> None:
        super().__init__(url, "Not found — package may not exist in this ecosystem")


class ValidationError(TrustwatchError):
    """Raised when input validation fails."""

    def __init__(self, field: str, value: object, reason: str) -> None:
        self.field  = field
        self.value  = value
        self.reason = reason
        super().__init__(f"Invalid {field}={value!r}: {reason}")


class ParseError(TrustwatchError):
    """Raised when a manifest file cannot be parsed."""

    def __init__(self, filepath: str, reason: str) -> None:
        self.filepath = filepath
        self.reason   = reason
        super().__init__(f"Cannot parse {filepath}: {reason}")


class HistoryError(TrustwatchError):
    """Raised when history database operations fail."""
