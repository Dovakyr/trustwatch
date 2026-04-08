"""
models.py — typed dataclasses for all trustwatch data structures.

Every function that previously returned a raw dict now returns one of these.
Benefits:
  - Shape is enforced at construction, not guessed by callers
  - IDE autocomplete works everywhere
  - Mistakes caught at import time, not runtime
  - Clean JSON serialisation via asdict()
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Signal results ─────────────────────────────────────────────────────────────

@dataclass
class SignalResult:
    """Base for all signal results — every signal returns one of these."""
    score: int                    # 0–100
    detail: str                   # human-readable explanation
    data_source: str = "unknown"  # github | registry | none

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PublishConcentrationResult(SignalResult):
    effective_publisher_count: Optional[int] = None
    trusted_org: bool = False


@dataclass
class MaintainerSpofResult(SignalResult):
    top_author: Optional[str] = None
    top_author_share_pct: Optional[float] = None
    human_author_count: Optional[int] = None
    bots_excluded: int = 0


@dataclass
class TokenAgeResult(SignalResult):
    last_modified: Optional[str] = None
    age_days: Optional[int] = None


@dataclass
class ActivityDeltaResult(SignalResult):
    recent_publish_count: int = 0
    flags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # detail for ActivityDelta comes from flags, not a single string
        if not self.detail and self.flags:
            self.detail = self.flags[0]


@dataclass
class GitHubHealthResult(SignalResult):
    stars: int = 0
    archived: bool = False
    flags: list[str] = field(default_factory=list)


# ── Signals bundle ─────────────────────────────────────────────────────────────

@dataclass
class Signals:
    publish_concentration: PublishConcentrationResult
    maintainer_spof:       MaintainerSpofResult
    token_age_risk:        TokenAgeResult
    activity_delta:        ActivityDeltaResult
    github_health:         GitHubHealthResult

    def to_dict(self) -> dict:
        return {
            "publish_concentration": asdict(self.publish_concentration),
            "maintainer_spof":       asdict(self.maintainer_spof),
            "token_age_risk":        asdict(self.token_age_risk),
            "activity_delta":        asdict(self.activity_delta),
            "github_health":         asdict(self.github_health),
        }


# ── Blast radius ───────────────────────────────────────────────────────────────

@dataclass
class BlastRadius:
    dependent_count: Optional[int]
    impact: str   # minimal | low | medium | high | very_high | critical_infrastructure | unknown
    source: str = "deps.dev"

    def to_dict(self) -> dict:
        return asdict(self)


# ── Risk assessment ────────────────────────────────────────────────────────────

@dataclass
class RiskAssessment:
    overall_score: int
    level: str                            # LOW | MEDIUM | HIGH | CRITICAL
    signals: Signals
    patterns_triggered: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overall_score":      self.overall_score,
            "level":              self.level,
            "signals":            self.signals.to_dict(),
            "patterns_triggered": self.patterns_triggered,
        }


# ── Scan config ────────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """
    All scan parameters in one place.
    Replaces global _no_github flag and scattered parameter passing.
    """
    days: int = 90
    token: Optional[str] = None
    no_github: bool = False

    def __post_init__(self) -> None:
        if self.days < 1 or self.days > 3650:
            raise ValueError(f"days must be between 1 and 3650, got {self.days}")


# ── GitHub data ────────────────────────────────────────────────────────────────

@dataclass
class GitHubData:
    slug: str
    stars: int = 0
    forks: int = 0
    open_issues: int = 0
    archived: bool = False
    pushed_at: str = ""
    default_branch: str = "main"
    recent_commit_authors: dict[str, int] = field(default_factory=dict)
    recent_commit_author_count: int = 0
    recent_releases: list[dict] = field(default_factory=list)
    recent_release_count: int = 0
    recent_release_publishers: list[str] = field(default_factory=list)
    recent_release_publisher_count: int = 0
    top_contributors: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ── Raw scan result ────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """
    Raw data from the scanner — before scoring.
    The scorer takes a ScanResult and returns a Report.
    """
    ecosystem: str
    package: str
    latest_version: str = ""
    total_versions: int = 0
    maintainers: list[str] = field(default_factory=list)
    maintainer_count: int = 0
    recent_publishes: list[dict] = field(default_factory=list)
    recent_publisher_count: int = 0
    recent_publishers: list[str] = field(default_factory=list)
    modified: str = ""
    created: str = ""
    github: Optional[GitHubData] = None
    github_slug_found: Optional[str] = None
    github_error: Optional[str] = None
    blast_radius: Optional[BlastRadius] = None
    pypi_roles: Optional[dict] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ── Final scored report ────────────────────────────────────────────────────────

@dataclass
class Report:
    """
    Final output of a scan — scan result + risk assessment.
    This is what gets serialised to JSON, stored in history, and displayed.
    """
    trustwatch: str
    scanned_at: str
    package: str
    ecosystem: str
    latest_version: str
    risk: RiskAssessment
    blast_radius: BlastRadius
    summary: list[str]
    delta: Optional[dict] = None   # populated after history lookup

    def to_dict(self) -> dict:
        return {
            "trustwatch":     self.trustwatch,
            "scanned_at":     self.scanned_at,
            "package":        self.package,
            "ecosystem":      self.ecosystem,
            "latest_version": self.latest_version,
            "risk":           self.risk.to_dict(),
            "blast_radius":   self.blast_radius.to_dict() if self.blast_radius else None,
            "summary":        self.summary,
            "delta":          self.delta,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# ── History record ─────────────────────────────────────────────────────────────

@dataclass
class HistoryRecord:
    id: int
    package: str
    ecosystem: str
    scanned_at: str
    score: int
    level: str
    summary: list[str]
    signals: dict


# ── Delta ──────────────────────────────────────────────────────────────────────

@dataclass
class Delta:
    previous_score: Optional[int]
    previous_level: Optional[str]
    delta: Optional[int]
    days_since_last: Optional[int]
    trend: str
    history_count: int

    def to_dict(self) -> dict:
        return asdict(self)
