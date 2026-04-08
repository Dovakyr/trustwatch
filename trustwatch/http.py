"""
http.py — HTTP client for trustwatch.

Single responsibility: make GET requests and return parsed JSON.
All error handling is explicit — no bare excepts, no silent failures.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Optional

from .constants import HTTP_TIMEOUT_SECONDS, GITHUB_API, VERSION
from .exceptions import NetworkError, RateLimitError, NotFoundError

logger = logging.getLogger(__name__)


def get(url: str, token: Optional[str] = None) -> dict:
    """
    GET a URL and return parsed JSON.

    Args:
        url:   Full URL to fetch.
        token: Optional Bearer token (GitHub PAT).

    Returns:
        Parsed JSON response as dict.

    Raises:
        RateLimitError:  GitHub 403 — rate limit hit.
        NotFoundError:   HTTP 404 — resource doesn't exist.
        NetworkError:    Any other network or HTTP failure.
    """
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", f"trustwatch/{VERSION}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    logger.debug("GET %s", url)

    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body)

    except urllib.error.HTTPError as exc:
        if exc.code == 403 and GITHUB_API in url:
            raise RateLimitError(url) from exc
        if exc.code == 404:
            raise NotFoundError(url) from exc
        raise NetworkError(url, f"HTTP {exc.code}") from exc

    except urllib.error.URLError as exc:
        raise NetworkError(url, str(exc.reason)) from exc

    except json.JSONDecodeError as exc:
        raise NetworkError(url, f"Invalid JSON response: {exc}") from exc
