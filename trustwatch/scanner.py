"""
scanner.py — fetches raw data from package registries.

Design principles:
  - All functions return typed ScanResult, not raw dicts
  - GitHub data is always best-effort — failures populate github_error
  - Input is validated before any network call
  - Explicit exception types, no bare excepts
  - Late-binding imports removed — all at top of file
"""

from __future__ import annotations

import logging
import re
import xmlrpc.client as xmlrpc
from datetime import datetime, timezone, timedelta
from typing import Optional

from .constants import (
    GITHUB_MAX_COMMITS, GITHUB_MAX_RELEASES, GITHUB_MAX_CONTRIBUTORS,
    DEPS_DEV_BASE, NPM_REGISTRY, PYPI_JSON_BASE, GITHUB_API,
)
from .exceptions import NetworkError, NotFoundError, RateLimitError
from .http import get
from .models import ScanResult, GitHubData, BlastRadius, ScanConfig
from .scorer import blast_label

logger = logging.getLogger(__name__)


# ── Utilities ─────────────────────────────────────────────────────────────────

_GH_SLUG_RE = re.compile(
    r"github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)"
    r"(?:\.git|#[^/]*)?(?:/|$)"
)


def _extract_gh_slug(url: str) -> str:
    """Extract 'owner/repo' from any GitHub URL format. Returns '' if not found."""
    if not url:
        return ""
    m = _GH_SLUG_RE.search(url)
    return m.group(1) if m else ""


def _since(days: int) -> str:
    """ISO-8601 timestamp N days ago (UTC)."""
    return (
        datetime.now(timezone.utc) - timedelta(days=days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── deps.dev ──────────────────────────────────────────────────────────────────

_DEPSDEV_ECO = {
    "npm":   "NPM",
    "pypi":  "PYPI",
    "cargo": "CARGO",
    "maven": "MAVEN",
    "nuget": "NUGET",
    "go":    "GO",
}


def resolve_github_via_depsdev(package: str, ecosystem: str) -> str:
    """
    Use deps.dev v3 API to find the GitHub repo for a package.

    Returns owner/repo slug or empty string if not found or API unavailable.
    Failure is non-fatal — GitHub link is enrichment, not required.
    """
    sys_name = _DEPSDEV_ECO.get(ecosystem.lower(), "")
    if not sys_name:
        return ""

    url = f"{DEPS_DEV_BASE}/systems/{sys_name}/packages/{package}"
    try:
        data = get(url)
    except (NetworkError, NotFoundError):
        logger.debug("deps.dev unavailable for %s/%s", ecosystem, package)
        return ""

    for link in data.get("sourceCodeLinks", []):
        slug = _extract_gh_slug(link.get("url", "") or link.get("link", ""))
        if slug:
            return slug

    for version in data.get("versions", [])[:1]:
        for link in version.get("links", []):
            slug = _extract_gh_slug(link.get("url", "") or link.get("link", ""))
            if slug:
                return slug

    return ""


def get_blast_radius(package: str, ecosystem: str) -> BlastRadius:
    """
    Use deps.dev to get dependent count for blast radius scoring.

    Returns BlastRadius with dependent_count=None on failure.
    """
    sys_name = _DEPSDEV_ECO.get(ecosystem.lower(), "")
    if not sys_name:
        return BlastRadius(dependent_count=None, impact="unknown",
                           source="unsupported")

    url = f"{DEPS_DEV_BASE}/systems/{sys_name}/packages/{package}"
    try:
        data = get(url)
    except (NetworkError, NotFoundError):
        logger.debug("deps.dev blast radius unavailable for %s/%s",
                     ecosystem, package)
        return BlastRadius(dependent_count=None, impact="unknown",
                           source="unavailable")

    count: Optional[int] = data.get("dependentCount")
    if count is None:
        for version in data.get("versions", []):
            if version.get("isDefault") or version.get("isLatest"):
                count = version.get("dependentCount")
                break

    return BlastRadius(
        dependent_count = count,
        impact          = blast_label(count),
        source          = "deps.dev",
    )


# ── GitHub ────────────────────────────────────────────────────────────────────

def fetch_github(slug: str, cfg: ScanConfig) -> GitHubData:
    """
    Fetch GitHub repo metadata and contributor activity.

    Args:
        slug: owner/repo format.
        cfg:  ScanConfig with token and days.

    Returns:
        GitHubData populated from API responses.

    Raises:
        RateLimitError: If unauthenticated rate limit is hit.
        NetworkError:   On other HTTP or network failures.
    """
    token = cfg.token
    repo  = get(f"{GITHUB_API}/repos/{slug}", token)
    since = _since(cfg.days)

    # Recent commits — best effort
    commit_authors: dict[str, int] = {}
    try:
        raw = get(
            f"{GITHUB_API}/repos/{slug}/commits"
            f"?since={since}&per_page={GITHUB_MAX_COMMITS}",
            token,
        )
        commits = raw if isinstance(raw, list) else []
        for c in commits:
            author = (
                (c.get("author") or {}).get("login")
                or (c.get("commit", {}).get("author") or {}).get("name", "unknown")
            )
            commit_authors[author] = commit_authors.get(author, 0) + 1
    except NetworkError as exc:
        logger.warning("Could not fetch commits for %s: %s", slug, exc)

    # Recent releases — best effort
    recent_releases: list[dict] = []
    release_publishers: set[str] = set()
    cutoff = datetime.now(timezone.utc) - timedelta(days=cfg.days)

    try:
        raw = get(
            f"{GITHUB_API}/repos/{slug}/releases"
            f"?per_page={GITHUB_MAX_RELEASES}",
            token,
        )
        releases = raw if isinstance(raw, list) else []
        for r in releases:
            pub_str = r.get("published_at", "") or ""
            try:
                ts = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            except ValueError:
                continue
            if ts < cutoff:
                continue
            publisher = (r.get("author") or {}).get("login", "unknown")
            recent_releases.append({
                "tag":          r.get("tag_name", ""),
                "published_at": pub_str,
                "publisher":    publisher,
                "prerelease":   r.get("prerelease", False),
            })
            release_publishers.add(publisher)
    except NetworkError as exc:
        logger.warning("Could not fetch releases for %s: %s", slug, exc)

    # If no GitHub Releases found, fall back to git tags
    # Many projects (esp. older ones) use tags rather than GitHub Releases
    if not recent_releases:
        try:
            raw = get(
                f"{GITHUB_API}/repos/{slug}/tags?per_page={GITHUB_MAX_RELEASES}",
                token,
            )
            tags = raw if isinstance(raw, list) else []
            # Tags don't have published_at — use pushed_at as proxy
            for t in tags[:5]:
                commit_url = (t.get("commit") or {}).get("url", "")
                if commit_url:
                    try:
                        commit = get(commit_url, token)
                        tag_date = (
                            commit.get("commit", {})
                            .get("author", {})
                            .get("date", "")
                        )
                        if tag_date:
                            ts = datetime.fromisoformat(tag_date.replace("Z", "+00:00"))
                            if ts >= cutoff:
                                recent_releases.append({
                                    "tag":          t.get("name", ""),
                                    "published_at": tag_date,
                                    "publisher":    "unknown",
                                    "prerelease":   False,
                                    "source":       "tag",
                                })
                                release_publishers.add("unknown")
                    except NetworkError:
                        pass
        except NetworkError as exc:
            logger.debug("Could not fetch tags for %s: %s", slug, exc)

    # All-time top contributors — best effort
    top_contributors: list[dict] = []
    try:
        raw = get(
            f"{GITHUB_API}/repos/{slug}/contributors"
            f"?per_page={GITHUB_MAX_CONTRIBUTORS}",
            token,
        )
        contribs = raw if isinstance(raw, list) else []
        top_contributors = [
            {"login": c.get("login", ""), "contributions": c.get("contributions", 0)}
            for c in contribs[:10]
        ]
    except NetworkError as exc:
        logger.warning("Could not fetch contributors for %s: %s", slug, exc)

    return GitHubData(
        slug                          = slug,
        stars                         = repo.get("stargazers_count", 0),
        forks                         = repo.get("forks_count", 0),
        open_issues                   = repo.get("open_issues_count", 0),
        archived                      = repo.get("archived", False),
        pushed_at                     = repo.get("pushed_at", ""),
        default_branch                = repo.get("default_branch", "main"),
        recent_commit_authors         = commit_authors,
        recent_commit_author_count    = len(commit_authors),
        recent_releases               = recent_releases,
        recent_release_count          = len(recent_releases),
        recent_release_publishers     = list(release_publishers),
        recent_release_publisher_count = len(release_publishers),
        top_contributors              = top_contributors,
    )


def _try_fetch_github(
    slug: str, cfg: ScanConfig
) -> tuple[Optional[GitHubData], Optional[str]]:
    """
    Attempt GitHub fetch. Returns (data, None) on success, (None, error) on failure.
    Never raises — GitHub is enrichment, not required.
    """
    if not slug or cfg.no_github:
        return None, None
    try:
        return fetch_github(slug, cfg), None
    except RateLimitError as exc:
        logger.warning("GitHub rate limit: %s", exc)
        return None, str(exc)
    except NotFoundError:
        logger.debug("GitHub repo not found: %s", slug)
        return None, f"Repository not found: {slug}"
    except NetworkError as exc:
        logger.warning("GitHub unavailable for %s: %s", slug, exc)
        return None, str(exc)


# ── PyPI roles via XMLRPC ─────────────────────────────────────────────────────

def get_pypi_roles(package: str) -> dict:
    """
    Fetch owner/maintainer list via PyPI XMLRPC API.

    Returns dict with owners, maintainers, total_count.
    Returns empty lists on failure — PyPI XMLRPC is best-effort.
    """
    try:
        client = xmlrpc.ServerProxy(PYPI_JSON_BASE)
        roles  = client.package_roles(package)
        owners      = [u for role, u in roles if role == "Owner"]
        maintainers = [u for role, u in roles if role == "Maintainer"]
        return {
            "owners":      owners,
            "maintainers": maintainers,
            "total_count": len(owners) + len(maintainers),
            "source":      "xmlrpc",
        }
    except Exception as exc:   # xmlrpc raises various types
        logger.debug("PyPI XMLRPC unavailable for %s: %s", package, exc)
        return {
            "owners": [], "maintainers": [], "total_count": 0,
            "source": "xmlrpc", "error": str(exc),
        }




# ── GitHub slug extraction helpers ───────────────────────────────────────────

# PyPI project_urls key names that commonly contain a GitHub link.
# Ordered by reliability — Source/Repository first, issue trackers last.
_PYPI_GITHUB_KEYS = (
    "Source", "Source Code", "source", "source_code",
    "Repository", "repository", "Repo",
    "Code", "code",
    "Homepage", "homepage",
    "GitHub", "Github", "github",
    "Bug Tracker", "Bugs", "Issues",   # often points to /issues — still parseable
)


def _extract_npm_github_slug(reg: dict) -> str:
    """
    Extract GitHub slug from npm registry metadata.

    Tries in order:
      1. Top-level repository.url (object form)
      2. Top-level repository as plain string
      3. Top-level homepage
      4. Top-level bugs.url
      5. Latest version metadata (repository, homepage, bugs) —
         some packages don't hoist these to the top level
    """
    slug = _extract_npm_github_slug_from(reg)
    if slug:
        return slug

    # Fallback: check latest version metadata
    # The npm registry *should* hoist repository to top level but
    # some packages (e.g. crypto-js) only have it in the version object
    latest_tag = (reg.get("dist-tags") or {}).get("latest", "")
    if latest_tag:
        latest_meta = (reg.get("versions") or {}).get(latest_tag, {})
        if latest_meta:
            slug = _extract_npm_github_slug_from(latest_meta)
            if slug:
                return slug

    return ""


def _extract_npm_github_slug_from(meta: dict) -> str:
    """Extract GitHub slug from a single metadata dict (top-level or version)."""
    repo = meta.get("repository")
    if isinstance(repo, dict):
        url = repo.get("url", "")
    elif isinstance(repo, str):
        url = repo
    else:
        url = ""

    slug = _extract_gh_slug(url)
    if slug:
        return slug

    # homepage fallback
    slug = _extract_gh_slug(meta.get("homepage", "") or "")
    if slug:
        return slug

    # bugs.url fallback
    bugs = meta.get("bugs")
    bugs_url = (
        bugs.get("url", "") if isinstance(bugs, dict)
        else (bugs if isinstance(bugs, str) else "")
    ) or ""
    return _extract_gh_slug(bugs_url)


def _extract_pypi_github_slug(info: dict) -> str:
    """
    Extract GitHub slug from PyPI JSON API info block.

    Tries all known project_urls key variants, then home_page,
    then author_email (some packages embed the URL there).
    """
    project_urls = info.get("project_urls") or {}

    # Try all known key variants
    for key in _PYPI_GITHUB_KEYS:
        url = project_urls.get(key, "")
        if url:
            slug = _extract_gh_slug(url)
            if slug:
                return slug

    # Top-level home_page field
    slug = _extract_gh_slug(info.get("home_page", "") or "")
    if slug:
        return slug

    # description sometimes has the GitHub URL in the first line
    # (common in older packages) — check only if it starts with https://github.com
    desc = (info.get("description", "") or "").strip()
    first_line = desc.split("\n")[0].strip()
    if first_line.startswith("https://github.com"):
        slug = _extract_gh_slug(first_line)
        if slug:
            return slug

    return ""


# ── npm ───────────────────────────────────────────────────────────────────────

def scan_npm(package: str, cfg: ScanConfig) -> ScanResult:
    """Scan an npm package. Raises ScanError if registry is unreachable."""
    from datetime import timedelta

    reg = get(f"{NPM_REGISTRY}/{package}")

    versions    = reg.get("versions", {})
    times       = reg.get("time", {})
    maintainers = reg.get("maintainers", [])
    latest      = reg.get("dist-tags", {}).get("latest", "")

    cutoff = datetime.now(timezone.utc) - timedelta(days=cfg.days)
    recent_publishes: list[dict] = []
    publishers: set[str] = set()

    for ver, ts_str in times.items():
        if ver in ("created", "modified"):
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            continue
        if ts < cutoff:
            continue
        pub = versions.get(ver, {}).get("_npmUser", {}).get("name", "unknown")
        recent_publishes.append({
            "version": ver, "published_at": ts_str, "publisher": pub
        })
        if pub != "unknown":
            publishers.add(pub)

    # Fallback: some packages don't hoist maintainers to top level
    if not maintainers:
        latest_tag = (reg.get("dist-tags") or {}).get("latest", "")
        if latest_tag:
            latest_meta = (reg.get("versions") or {}).get(latest_tag, {})
            maintainers = latest_meta.get("maintainers", [])

    maintainer_names = [m.get("name", "") for m in maintainers if m.get("name")]

    gh_slug = _extract_npm_github_slug(reg)
    if not gh_slug and not cfg.no_github:
        gh_slug = resolve_github_via_depsdev(package, "npm")

    github_data, github_error = _try_fetch_github(gh_slug, cfg)
    blast = get_blast_radius(package, "npm")

    return ScanResult(
        ecosystem              = "npm",
        package                = package,
        latest_version         = latest,
        total_versions         = len(versions),
        maintainers            = maintainer_names,
        maintainer_count       = len(maintainer_names),
        recent_publishes       = recent_publishes,
        recent_publisher_count = len(publishers),
        recent_publishers      = list(publishers),
        modified               = times.get("modified", ""),
        created                = times.get("created", ""),
        github                 = github_data,
        github_slug_found      = gh_slug or None,
        github_error           = github_error,
        blast_radius           = blast,
    )


# ── PyPI ──────────────────────────────────────────────────────────────────────

def scan_pypi(package: str, cfg: ScanConfig) -> ScanResult:
    """Scan a PyPI package. Raises ScanError if registry is unreachable."""
    data     = get(f"{PYPI_JSON_BASE}/{package}/json")
    info     = data.get("info", {})
    releases = data.get("releases", {})

    cutoff = datetime.now(timezone.utc) - timedelta(days=cfg.days)
    recent_publishes: list[dict] = []

    for ver, files in releases.items():
        for f in files:
            # Skip yanked files — they were pulled for a reason
            if f.get("yanked"):
                continue

            # upload_time_iso_8601 is the modern field; older PyPI files use upload_time
            upload_time = (
                f.get("upload_time_iso_8601", "")
                or f.get("upload_time", "")
            )
            if not upload_time:
                continue
            # Normalise to ISO format with timezone
            if upload_time and "T" in upload_time and "+" not in upload_time and not upload_time.endswith("Z"):
                upload_time = upload_time + "+00:00"
            try:
                ts = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
            except ValueError:
                continue
            if ts >= cutoff:
                recent_publishes.append({
                    "version":      ver,
                    "published_at": upload_time,
                    "filename":     f.get("filename", ""),
                })
                break   # one entry per version

    gh_slug = _extract_pypi_github_slug(info)
    if not gh_slug and not cfg.no_github:
        gh_slug = resolve_github_via_depsdev(package, "pypi")

    github_data, github_error = _try_fetch_github(gh_slug, cfg)
    blast = get_blast_radius(package, "pypi")

    # PyPI XMLRPC for accurate maintainer list
    roles            = get_pypi_roles(package)
    maintainer_count = roles["total_count"] if roles["total_count"] > 0 else (
        1 if info.get("maintainer") else 0
    )
    maintainer_names = roles["owners"] + roles["maintainers"]
    if not maintainer_names and info.get("maintainer"):
        maintainer_names = [info["maintainer"]]

    return ScanResult(
        ecosystem              = "pypi",
        package                = package,
        latest_version         = info.get("version", ""),
        total_versions         = len(releases),
        maintainers            = maintainer_names,
        maintainer_count       = maintainer_count,
        recent_publishes       = recent_publishes,
        recent_publisher_count = len(recent_publishes),
        recent_publishers      = [],
        modified               = "",
        created                = "",
        github                 = github_data,
        github_slug_found      = gh_slug or None,
        github_error           = github_error,
        blast_radius           = blast,
        pypi_roles             = roles,
    )


# ── GitHub direct ─────────────────────────────────────────────────────────────

def scan_github(slug: str, cfg: ScanConfig) -> ScanResult:
    """Scan a GitHub repo directly by org/repo slug."""
    github_data, github_error = _try_fetch_github(slug, cfg)
    blast = get_blast_radius(slug.split("/")[-1], "github")

    return ScanResult(
        ecosystem         = "github",
        package           = slug,
        github            = github_data,
        github_slug_found = slug,
        github_error      = github_error,
        blast_radius      = blast,
    )


# ── Router ────────────────────────────────────────────────────────────────────

def scan_package(package: str, ecosystem: str, cfg: ScanConfig) -> ScanResult:
    """
    Route to the appropriate scanner.

    Args:
        package:   Validated package name or org/repo slug.
        ecosystem: One of: npm, pypi, github.
        cfg:       Scan configuration.

    Returns:
        ScanResult — never None.

    Raises:
        NetworkError:  If the registry is unreachable.
        NotFoundError: If the package doesn't exist.
        ValueError:    If ecosystem is unknown (should be caught by validation).
    """
    logger.info("Scanning %s (%s)", package, ecosystem)

    if ecosystem == "npm":
        return scan_npm(package, cfg)
    if ecosystem == "pypi":
        return scan_pypi(package, cfg)
    if ecosystem == "github":
        return scan_github(package, cfg)

    raise ValueError(f"Unknown ecosystem: {ecosystem!r}")
