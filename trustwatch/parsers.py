"""
parsers.py — read package lists from manifest files.

Supported formats:
  requirements.txt  → [(package, "pypi"), ...]
  package.json      → [(package, "npm"),  ...]
  plain .txt list   → [(package, eco),    ...]

Design: parsers are lenient — they skip lines they don't understand
rather than crashing. Security tooling that breaks on imperfect input
gets disabled.
"""

from __future__ import annotations

import json
import logging
import pathlib
import re
from typing import Optional

from .exceptions import ParseError

logger = logging.getLogger(__name__)

_VER_RE = re.compile(r"[><=!~;@]")

PackageList = list[tuple[str, str]]  # (package_name, ecosystem)


def parse_requirements_txt(text: str) -> PackageList:
    """
    Parse pip requirements.txt format.

    Handles version pins (==, >=, <=, ~=, !=), extras ([security]),
    -r includes (skipped), comments, VCS installs (skipped).

    Returns:
        List of (package_name, "pypi") tuples.
    """
    entries: PackageList = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        # skip empty, comments, options, VCS
        if not line:
            continue
        if line.startswith(("#", "-", "http://", "https://", "git+", ".")):
            continue

        # strip extras like requests[security]
        line = line.split("[")[0]

        # strip version specifiers and environment markers
        pkg = _VER_RE.split(line)[0].strip()
        if pkg:
            entries.append((pkg, "pypi"))

    return entries


def parse_package_json(text: str) -> PackageList:
    """
    Parse npm package.json.

    Reads: dependencies, devDependencies, peerDependencies.
    Skips: file:, workspace:, link: references (local packages).

    Returns:
        List of (package_name, "npm") tuples.

    Raises:
        ParseError: If the JSON is malformed.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError("package.json", f"Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ParseError("package.json", "Expected a JSON object at top level")

    entries: PackageList = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        section_data = data.get(section)
        if not isinstance(section_data, dict):
            continue
        for pkg, ver in section_data.items():
            if isinstance(ver, str) and ver.startswith(("file:", "workspace:", "link:")):
                logger.debug("Skipping local package: %s", pkg)
                continue
            entries.append((pkg, "npm"))

    return entries


def parse_plain_txt(text: str) -> PackageList:
    """
    Parse plain text watchlist.

    Supported line formats:
        lodash                      → ("lodash", "auto")
        lodash npm                  → ("lodash", "npm")
        requests pypi               → ("requests", "pypi")
        aquasecurity/trivy github   → ("aquasecurity/trivy", "github")
        # comment                   → skipped

    Returns:
        List of (package_name, ecosystem_or_"auto") tuples.
    """
    entries: PackageList = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        pkg   = parts[0]
        eco   = parts[1].lower() if len(parts) >= 2 else "auto"
        entries.append((pkg, eco))

    return entries


def detect_and_parse(filepath: str) -> PackageList:
    """
    Auto-detect manifest format from filename and parse.

    Args:
        filepath: Path to requirements.txt, package.json, or plain .txt file.

    Returns:
        List of (package_name, ecosystem) tuples.
        Ecosystem may be "auto" for plain lists without explicit ecosystem.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ParseError:        If the file format is unsupported or malformed.
    """
    p = pathlib.Path(filepath)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    text = p.read_text(encoding="utf-8", errors="replace")
    name = p.name.lower()

    if name == "package.json":
        return parse_package_json(text)

    requirements_names = {
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "dev-requirements.txt",
        "test-requirements.txt",
        "requirements-ci.txt",
    }
    if name in requirements_names:
        return parse_requirements_txt(text)

    if name.endswith(".txt"):
        # Heuristic: if it contains version operators, treat as requirements
        if any(op in text for op in ("==", ">=", "<=")):
            return parse_requirements_txt(text)
        return parse_plain_txt(text)

    raise ParseError(
        filepath,
        f"Unsupported file type: {name!r}. "
        "Supported: package.json, requirements.txt, or plain .txt watchlist",
    )
