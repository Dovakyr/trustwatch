"""
constants.py — all configuration values in one place.

Rule: no magic number or magic string appears anywhere else in the codebase.
If you need to tune scoring, this is the only file you touch.
"""

from __future__ import annotations

# ── Version ───────────────────────────────────────────────────────────────────

VERSION = "0.4.0"


# ── Bot / automation account patterns ────────────────────────────────────────
# Matched via substring — account names containing any of these are excluded
# from SPOF and new-actor signals.

BOT_PATTERNS: tuple[str, ...] = (
    "-bot", "-automation", "[bot]", "-ci", "-robot",
    "dependabot", "renovate-bot", "renovate[bot]",
    "github-actions", "github-actions[bot]",
    "semantic-release-bot", "greenkeeper-bot",
    "snyk-bot", "whitesource-bolt",
    "aws-sdk-python-automation",
    "release-please", "copilot-swe-agent",
    "codecov-commenter", "allcontributors",
)


# ── Trusted organisations ─────────────────────────────────────────────────────
# Orgs with known governance structures: MFA requirements, succession plans,
# formal security policies. Publish concentration and SPOF scores are reduced
# by ORG_TRUST_REDUCTION points for packages under these orgs.

TRUSTED_ORGS: frozenset[str] = frozenset({
    # Python
    "psf", "python", "pypa", "numpy", "scipy", "pandas-dev",
    "scikit-learn", "django", "pallets", "encode", "tiangolo", "pydantic",
    # JavaScript
    "openjs-foundation", "expressjs", "nodejs", "eslint", "prettier",
    "sindresorhus", "babel", "webpack", "vitejs",
    # JVM
    "apache", "spring-projects", "grpc",
    # Cloud / infra
    "google", "googleapis", "aws", "microsoft", "azure",
    "hashicorp", "prometheus", "grafana", "cncf",
    # Security
    "sigstore", "openssf", "slsa-framework", "aquasecurity",
})


# ── Known PyPI packages ───────────────────────────────────────────────────────
# Used for ecosystem auto-detection: `trustwatch scan requests` → pypi.

KNOWN_PYPI: frozenset[str] = frozenset({
    "requests", "numpy", "pandas", "flask", "django", "fastapi",
    "boto3", "botocore", "pip", "setuptools", "wheel",
    "scipy", "matplotlib", "sqlalchemy", "pydantic", "celery",
    "pytest", "black", "mypy", "cryptography", "paramiko",
    "httpx", "aiohttp", "uvicorn", "gunicorn", "pillow",
    "tensorflow", "torch", "scikit-learn", "transformers",
    "langchain", "litellm", "openai", "anthropic",
    "rich", "typer", "click", "tqdm", "attrs",
    "urllib3", "certifi", "charset-normalizer", "idna",
})


# ── Risk level thresholds ─────────────────────────────────────────────────────

SCORE_CRITICAL: int = 75
SCORE_HIGH:     int = 55
SCORE_MEDIUM:   int = 35
# below SCORE_MEDIUM → LOW


# ── Signal weights ────────────────────────────────────────────────────────────
# Must sum to 1.0. Tuned against real-data validation set.

SIGNAL_WEIGHTS: dict[str, float] = {
    "publish_concentration": 0.30,
    "maintainer_spof":       0.20,
    "token_age_risk":        0.10,
    "activity_delta":        0.30,
    "github_health":         0.10,
}

assert abs(sum(SIGNAL_WEIGHTS.values()) - 1.0) < 1e-9, "Signal weights must sum to 1.0"


# ── Pattern override floor ────────────────────────────────────────────────────
# When a known attack pattern is detected, overall score is floored at this value.
# Ensures pattern detection always yields CRITICAL regardless of weighted score.

PATTERN_OVERRIDE_FLOOR: int = 78   # just above SCORE_CRITICAL (75)


# ── Pattern detection thresholds ─────────────────────────────────────────────
# XZ-Utils pattern: new actor dominating commits + publishing releases

XZ_PATTERN_ACTIVITY_MIN:     int = 85   # activity_delta score threshold
XZ_PATTERN_CONCENTRATION_MIN: int = 70   # publish_concentration score threshold

# Burnout/abandonment pattern
BURNOUT_CONCENTRATION_MIN:   int = 90
BURNOUT_SPOF_MIN:            int = 90
BURNOUT_TOKEN_AGE_MIN:       int = 60

# Solo SPOF pattern
SOLO_SPOF_SCORE_MIN:         int = 75
SOLO_SPOF_HUMAN_COUNT:       int = 1

# Summary signal display threshold (signals above this appear in summary)
SUMMARY_SIGNAL_THRESHOLD:    int = 60


# ── Publish concentration scores ─────────────────────────────────────────────

CONCENTRATION_UNKNOWN:     int = 30   # PyPI blind spot — not alarming, just opaque
CONCENTRATION_NONE:        int = 50   # No publishers detected
CONCENTRATION_SINGLE:      int = 95   # One person can publish alone
CONCENTRATION_TWO:         int = 70   # Two people share rights
CONCENTRATION_SMALL:       int = 40   # 3–4 publishers
CONCENTRATION_DISTRIBUTED: int = 15   # 5+ publishers


# ── SPOF scores ───────────────────────────────────────────────────────────────

SPOF_SOLE_CONTRIBUTOR:     int = 95   # single human, 95%+ share
SPOF_EXTREME:              int = 90   # 90%+ share
SPOF_STRONG:               int = 70   # 70%+ share
SPOF_MODERATE:             int = 45   # 50%+ share
SPOF_DISTRIBUTED:          int = 15   # <50% share
SPOF_REGISTRY_SINGLE:      int = 85   # single maintainer, GitHub unavailable
SPOF_REGISTRY_TWO:         int = 55   # two maintainers, GitHub unavailable
SPOF_REGISTRY_MULTI:       int = 25   # 3+ maintainers, GitHub unavailable
SPOF_NO_DATA:              int = 40   # no data at all


# ── Token age scores ──────────────────────────────────────────────────────────

TOKEN_AGE_VERY_STALE_DAYS:  int = 730   # 2+ years
TOKEN_AGE_STALE_DAYS:       int = 365   # 1+ year
TOKEN_AGE_MODERATE_DAYS:    int = 90    # 3+ months

TOKEN_AGE_VERY_STALE_SCORE: int = 85
TOKEN_AGE_STALE_SCORE:      int = 65
TOKEN_AGE_MODERATE_SCORE:   int = 35
TOKEN_AGE_FRESH_SCORE:      int = 10
TOKEN_AGE_UNKNOWN_SCORE:    int = 60


# ── Activity delta scores ─────────────────────────────────────────────────────

ACTIVITY_HIGH_VELOCITY_COUNT:   int = 10   # releases in window
ACTIVITY_HIGH_VELOCITY_SCORE:   int = 40
ACTIVITY_NEW_ACTOR_SCORE:       int = 55
ACTIVITY_XZ_PUBLISH_SCORE:      int = 35   # added on top of new actor score
ACTIVITY_ABANDONMENT_SCORE:     int = 30
ACTIVITY_MIN_VERSIONS_HISTORIC: int = 20   # min versions before abandonment flag


# ── GitHub health scores ──────────────────────────────────────────────────────

GITHUB_ARCHIVED_SCORE:        int = 80
GITHUB_ABANDONED_DAYS:        int = 365
GITHUB_ABANDONED_SCORE:       int = 50
GITHUB_LOW_ACTIVITY_DAYS:     int = 180
GITHUB_LOW_ACTIVITY_SCORE:    int = 25
GITHUB_OVERWHELMED_ISSUES:    int = 500
GITHUB_OVERWHELMED_SCORE:     int = 15
GITHUB_NO_DATA_SCORE:         int = 50


# ── Organisation trust reduction ─────────────────────────────────────────────

ORG_TRUST_REDUCTION: int = 25   # subtracted from concentration + SPOF scores


# ── Blast radius thresholds ───────────────────────────────────────────────────

BLAST_CRITICAL_INFRA:  int = 10_000_000
BLAST_VERY_HIGH:       int =  1_000_000
BLAST_HIGH:            int =    100_000
BLAST_MEDIUM:          int =     10_000
BLAST_LOW:             int =      1_000


# ── Operational ───────────────────────────────────────────────────────────────

BATCH_PAUSE_SECONDS:    float = 0.3    # between API calls in batch mode
CI_GATE_DEFAULT_SCORE:  int   = 75     # default --threshold for CI exit code
HTTP_TIMEOUT_SECONDS:   int   = 15
GITHUB_MAX_COMMITS:     int   = 100
GITHUB_MAX_RELEASES:    int   = 20
GITHUB_MAX_CONTRIBUTORS: int  = 30
HISTORY_DEFAULT_LIMIT:  int   = 10


# ── Trend thresholds ──────────────────────────────────────────────────────────

TREND_SHARP_DELTA:  int = 20
TREND_NORMAL_DELTA: int =  8
TREND_SLIGHT_DELTA: int =  2


# ── External APIs ─────────────────────────────────────────────────────────────

DEPS_DEV_BASE:  str = "https://api.deps.dev/v3"
NPM_REGISTRY:   str = "https://registry.npmjs.org"
PYPI_JSON_BASE: str = "https://pypi.org/pypi"
PYPI_XMLRPC:    str = "https://pypi.org/pypi"
GITHUB_API:     str = "https://api.github.com"
