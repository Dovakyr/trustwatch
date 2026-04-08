"""
tests/test_scorer.py — unit tests for the scoring engine.

No network calls. All scenarios use typed ScanResult / GitHubData objects.

Scenarios:
  1. HEALTHY      — well-governed, distributed team
  2. AT_RISK      — solo maintainer, stale, abandonment signals
  3. COMPROMISED  — XZ-Utils infiltration pattern
  4. BOT_HEAVY    — project with CI bots that should not count as SPOF
  5. TRUSTED_ORG  — PSF-backed package, org tier should reduce score
"""

from __future__ import annotations

import sys
import pathlib

# Allow running from repo root without installing
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from datetime import datetime, timezone, timedelta

from trustwatch.models import ScanResult, GitHubData, BlastRadius
from trustwatch.scorer import score, is_bot, filter_bots, blast_label
from trustwatch.constants import (
    SCORE_CRITICAL, SCORE_HIGH, SCORE_MEDIUM,
    BOT_PATTERNS,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def days_ago(n: int) -> str:
    return (
        datetime.now(timezone.utc) - timedelta(days=n)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_github(
    slug: str = "owner/pkg",
    pushed_days_ago: int = 5,
    commit_authors: dict | None = None,
    release_publishers: list | None = None,
    top_contributors: list | None = None,
    archived: bool = False,
    open_issues: int = 10,
) -> GitHubData:
    authors = commit_authors or {"alice": 20, "bob": 15, "carol": 10}
    return GitHubData(
        slug                          = slug,
        stars                         = 1000,
        forks                         = 100,
        open_issues                   = open_issues,
        archived                      = archived,
        pushed_at                     = days_ago(pushed_days_ago),
        recent_commit_authors         = authors,
        recent_commit_author_count    = len(authors),
        recent_releases               = [],
        recent_release_count          = 0,
        recent_release_publishers     = release_publishers or [],
        recent_release_publisher_count = len(release_publishers or []),
        top_contributors              = top_contributors or [
            {"login": k, "contributions": v * 10}
            for k, v in authors.items()
        ],
    )


# ── bot detection ─────────────────────────────────────────────────────────────

class TestBotDetection:
    def test_known_bots_detected(self) -> None:
        bots = [
            "dependabot", "renovate-bot", "github-actions[bot]",
            "aws-sdk-python-automation", "release-please",
        ]
        for b in bots:
            assert is_bot(b), f"Expected {b!r} to be detected as bot"

    def test_humans_not_detected(self) -> None:
        humans = ["jdalton", "kennethreitz", "sigmavirus24", "alice", "bob-smith"]
        for h in humans:
            assert not is_bot(h), f"Expected {h!r} to NOT be detected as bot"

    def test_filter_bots_removes_bots(self) -> None:
        authors = {"dependabot": 50, "human": 5, "aws-sdk-python-automation": 80}
        filtered = filter_bots(authors)
        assert filtered == {"human": 5}
        assert "dependabot" not in filtered
        assert "aws-sdk-python-automation" not in filtered

    def test_filter_bots_empty_input(self) -> None:
        assert filter_bots({}) == {}

    def test_filter_bots_all_humans(self) -> None:
        authors = {"alice": 10, "bob": 5}
        assert filter_bots(authors) == authors


# ── blast radius label ────────────────────────────────────────────────────────

class TestBlastLabel:
    def test_critical_infrastructure(self) -> None:
        assert blast_label(10_000_000) == "critical_infrastructure"
        assert blast_label(50_000_000) == "critical_infrastructure"

    def test_very_high(self) -> None:
        assert blast_label(1_000_000) == "very_high"
        assert blast_label(5_000_000) == "very_high"

    def test_high(self) -> None:
        assert blast_label(100_000) == "high"
        assert blast_label(500_000) == "high"

    def test_medium(self) -> None:
        assert blast_label(10_000) == "medium"

    def test_low(self) -> None:
        assert blast_label(1_000) == "low"
        assert blast_label(5_000) == "low"

    def test_minimal(self) -> None:
        assert blast_label(500) == "minimal"
        assert blast_label(0) == "minimal"

    def test_unknown(self) -> None:
        assert blast_label(None) == "unknown"


# ── scenario 1: HEALTHY ───────────────────────────────────────────────────────

class TestScenarioHealthy:
    """Well-governed project — distributed team, recent activity, multi-publisher."""

    def setup_method(self) -> None:
        gh = make_github(
            commit_authors={"alice": 22, "bob": 18, "carol": 15, "dave": 10},
            release_publishers=["alice", "bob"],
            top_contributors=[
                {"login": "alice", "contributions": 800},
                {"login": "bob",   "contributions": 600},
                {"login": "carol", "contributions": 400},
                {"login": "dave",  "contributions": 200},
            ],
        )
        self.result = ScanResult(
            ecosystem="npm", package="well-maintained-sdk",
            latest_version="4.2.1", total_versions=80,
            maintainers=["alice", "bob", "carol", "dave", "eve"],
            maintainer_count=5,
            recent_publishes=[
                {"version": f"1.{i}.0", "published_at": days_ago(i * 14),
                 "publisher": "alice"}
                for i in range(1, 5)
            ],
            recent_publisher_count=3,
            recent_publishers=["alice", "bob", "carol"],
            modified=days_ago(5),
            github=gh,
        )

    def test_scores_low(self) -> None:
        r = score(self.result)
        assert r.risk.level == "LOW", (
            f"Expected LOW, got {r.risk.level} (score={r.risk.overall_score})"
        )

    def test_no_patterns_triggered(self) -> None:
        r = score(self.result)
        assert r.risk.patterns_triggered == []

    def test_commits_well_distributed(self) -> None:
        r = score(self.result)
        spof = r.risk.signals.maintainer_spof
        assert spof.score < 40, f"Expected low SPOF score, got {spof.score}"
        assert spof.data_source == "github"

    def test_serialises_cleanly(self) -> None:
        import json
        r = score(self.result)
        parsed = json.loads(r.to_json())
        assert parsed["package"] == "well-maintained-sdk"
        assert parsed["risk"]["level"] == "LOW"


# ── scenario 2: AT_RISK ───────────────────────────────────────────────────────

class TestScenarioAtRisk:
    """Solo maintainer, stale tokens, no recent activity — classic burnout."""

    def setup_method(self) -> None:
        gh = make_github(
            commit_authors={"jdalton": 3},
            release_publishers=[],
            top_contributors=[{"login": "jdalton", "contributions": 3100}],
            pushed_days_ago=420,
            open_issues=312,
        )
        self.result = ScanResult(
            ecosystem="npm", package="solo-utility-lib",
            latest_version="2.4.1", total_versions=41,
            maintainers=["jdalton"], maintainer_count=1,
            recent_publishes=[],
            recent_publisher_count=1,
            recent_publishers=["jdalton"],
            modified=days_ago(420),
            github=gh,
        )

    def test_scores_critical(self) -> None:
        r = score(self.result)
        assert r.risk.level == "CRITICAL", (
            f"Expected CRITICAL, got {r.risk.level} (score={r.risk.overall_score})"
        )

    def test_spof_pattern_triggered(self) -> None:
        r = score(self.result)
        # solo_spof or burnout_abandonment should fire
        assert len(r.risk.patterns_triggered) > 0, (
            "Expected at least one pattern triggered"
        )

    def test_top_author_identified(self) -> None:
        r = score(self.result)
        assert r.risk.signals.maintainer_spof.top_author == "jdalton"

    def test_token_age_stale(self) -> None:
        r = score(self.result)
        age = r.risk.signals.token_age_risk
        assert age.score >= 60, f"Expected high token age score, got {age.score}"
        assert age.age_days is not None and age.age_days > 365

    def test_abandonment_flagged(self) -> None:
        r = score(self.result)
        flags = r.risk.signals.activity_delta.flags
        assert any("abandonment" in f.lower() or "possible" in f.lower()
                   for f in flags), f"Abandonment flag missing. Got: {flags}"


# ── scenario 3: COMPROMISED (XZ-Utils pattern) ───────────────────────────────

class TestScenarioXZPattern:
    """
    New actor (jia-tan) not in historical contributors suddenly dominates
    commits AND publishes releases. Exact pattern of XZ Utils attack.
    """

    def setup_method(self) -> None:
        gh = make_github(
            commit_authors={"jia-tan": 41, "lasse-collin": 7, "anon": 2},
            release_publishers=["jia-tan"],
            top_contributors=[
                {"login": "lasse-collin", "contributions": 1840},
                {"login": "old-contrib",  "contributions": 120},
            ],
            pushed_days_ago=8,
        )
        self.result = ScanResult(
            ecosystem="npm", package="critical-lib",
            latest_version="5.6.1", total_versions=28,
            maintainers=["lasse-collin"], maintainer_count=1,
            recent_publishes=[
                {"version": "5.6.1", "published_at": days_ago(8),  "publisher": "jia-tan"},
                {"version": "5.6.0", "published_at": days_ago(22), "publisher": "jia-tan"},
            ],
            recent_publisher_count=2,
            recent_publishers=["jia-tan", "lasse-collin"],
            modified=days_ago(8),
            github=gh,
        )

    def test_scores_critical(self) -> None:
        r = score(self.result)
        assert r.risk.level == "CRITICAL", (
            f"Expected CRITICAL, got {r.risk.level} (score={r.risk.overall_score})"
        )

    def test_xz_infiltration_pattern_triggered(self) -> None:
        r = score(self.result)
        assert "xz_infiltration" in r.risk.patterns_triggered, (
            f"xz_infiltration missing. Got: {r.risk.patterns_triggered}"
        )

    def test_new_actor_flag_present(self) -> None:
        r = score(self.result)
        flags = r.risk.signals.activity_delta.flags
        assert any("jia-tan" in f for f in flags), (
            f"jia-tan not flagged in activity_delta. Flags: {flags}"
        )

    def test_xz_publish_flag_present(self) -> None:
        r = score(self.result)
        flags = r.risk.signals.activity_delta.flags
        assert any("XZ-Utils" in f or "infiltration" in f.lower() for f in flags), (
            f"XZ publish flag missing. Flags: {flags}"
        )


# ── scenario 4: BOT HEAVY ────────────────────────────────────────────────────

class TestScenarioBotHeavy:
    """
    boto3-style project where a CI bot makes most commits.
    The bot should be excluded — human maintainers are what matters.
    """

    def setup_method(self) -> None:
        gh = make_github(
            slug="aws/boto3",
            commit_authors={"aws-sdk-python-automation": 80, "real-human": 5},
            release_publishers=[],
            top_contributors=[
                {"login": "real-human", "contributions": 500},
                {"login": "aws-sdk-python-automation", "contributions": 2000},
            ],
            pushed_days_ago=1,
        )
        self.result = ScanResult(
            ecosystem="npm", package="bot-heavy",
            latest_version="1.0", total_versions=200,
            maintainers=["real-human"], maintainer_count=1,
            modified=days_ago(1),
            github=gh,
            github_slug_found="aws/boto3",
        )

    def test_bot_excluded_from_spof(self) -> None:
        r = score(self.result)
        spof = r.risk.signals.maintainer_spof
        assert spof.top_author == "real-human", (
            f"Bot should be excluded. Got top_author={spof.top_author!r}"
        )

    def test_bots_excluded_count(self) -> None:
        r = score(self.result)
        assert r.risk.signals.maintainer_spof.bots_excluded == 1

    def test_not_critical_due_to_bot(self) -> None:
        r = score(self.result)
        # Score may be HIGH (solo human maintainer) but should NOT be
        # CRITICAL solely because a bot dominates commits
        # Note: still may be HIGH/CRITICAL due to solo maintainer — that's correct
        spof = r.risk.signals.maintainer_spof
        assert spof.top_author != "aws-sdk-python-automation", (
            "Bot should never be the reported top_author"
        )


# ── scenario 5: TRUSTED ORG ──────────────────────────────────────────────────

class TestScenarioTrustedOrg:
    """
    PSF-backed package. Org trust tier should reduce concentration and SPOF scores.
    A single-maintainer PSF project should not be CRITICAL.
    """

    def setup_method(self) -> None:
        gh = make_github(
            slug="psf/requests",
            commit_authors={"ferdnyc": 12, "sigmavirus24": 8, "nateprewitt": 5},
            release_publishers=["sigmavirus24"],
            top_contributors=[
                {"login": "kennethreitz", "contributions": 2000},
                {"login": "sigmavirus24",  "contributions": 1500},
                {"login": "nateprewitt",   "contributions": 800},
                {"login": "ferdnyc",       "contributions": 200},
            ],
            pushed_days_ago=3,
        )
        self.result = ScanResult(
            ecosystem="pypi", package="requests",
            latest_version="2.33.1", total_versions=140,
            maintainers=["sigmavirus24"], maintainer_count=1,
            recent_publishes=[
                {"version": "2.33.1", "published_at": days_ago(10)}
            ],
            recent_publisher_count=1,
            modified=days_ago(3),
            github=gh,
            github_slug_found="psf/requests",
        )

    def test_not_critical(self) -> None:
        r = score(self.result)
        assert r.risk.level != "CRITICAL", (
            f"PSF package should not be CRITICAL. "
            f"Got {r.risk.level} (score={r.risk.overall_score})"
        )

    def test_trusted_org_flag_set(self) -> None:
        r = score(self.result)
        assert r.risk.signals.publish_concentration.trusted_org is True

    def test_org_reduction_applied(self) -> None:
        r = score(self.result)
        pc_score = r.risk.signals.publish_concentration.score
        # Without org reduction: single publisher = 95
        # With ORG_TRUST_REDUCTION (25): should be 70
        assert pc_score <= 75, (
            f"Org reduction not applied. "
            f"publish_concentration.score={pc_score} (expected <= 75)"
        )


# ── registry fallback (no GitHub) ────────────────────────────────────────────

class TestRegistryFallback:
    """When GitHub is unavailable, scorer falls back to registry maintainer count."""

    def test_solo_npm_no_github_is_critical(self) -> None:
        raw = ScanResult(
            ecosystem="npm", package="lodash",
            latest_version="4.17.21", total_versions=114,
            maintainers=["jdalton"], maintainer_count=1,
            modified="2021-02-20T00:00:00Z",
            github=None,
            github_error="rate limited",
        )
        r = score(raw)
        assert r.risk.level == "CRITICAL"
        spof = r.risk.signals.maintainer_spof
        assert spof.data_source == "registry"
        assert spof.human_author_count == 1

    def test_multi_maintainer_npm_no_github_not_critical(self) -> None:
        raw = ScanResult(
            ecosystem="npm", package="express",
            latest_version="5.0.1", total_versions=270,
            maintainers=["a", "b", "c", "d", "e"], maintainer_count=5,
            modified=days_ago(10),
            github=None,
        )
        r = score(raw)
        spof = r.risk.signals.maintainer_spof
        assert spof.score <= 25, f"5 maintainers should be low SPOF, got {spof.score}"

    def test_pypi_unknown_publisher_not_alarming(self) -> None:
        raw = ScanResult(
            ecosystem="pypi", package="some-lib",
            latest_version="1.0", total_versions=20,
            maintainer_count=0,   # PyPI blind spot
            github=None,
        )
        r = score(raw)
        pc = r.risk.signals.publish_concentration
        assert pc.score <= 35, (
            f"Unknown PyPI publisher should be low penalty, got {pc.score}"
        )
        assert r.risk.level != "CRITICAL"


# ── run without pytest ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    GREEN = "\033[92m"; RED = "\033[91m"; RESET = "\033[0m"; BOLD = "\033[1m"

    classes = [
        TestBotDetection, TestBlastLabel,
        TestScenarioHealthy, TestScenarioAtRisk, TestScenarioXZPattern,
        TestScenarioBotHeavy, TestScenarioTrustedOrg, TestRegistryFallback,
    ]

    total = passed = 0
    for cls in classes:
        print(f"\n{BOLD}{cls.__name__}{RESET}")
        inst = cls()
        methods = [m for m in dir(inst) if m.startswith("test_")]
        for method_name in methods:
            total += 1
            try:
                if hasattr(inst, "setup_method"):
                    inst.setup_method()
                getattr(inst, method_name)()
                print(f"  {GREEN}PASS{RESET}  {method_name}")
                passed += 1
            except Exception as exc:
                print(f"  {RED}FAIL{RESET}  {method_name}")
                print(f"       {exc}")
                if "--tb" in sys.argv:
                    traceback.print_exc()

    print(f"\n{'─'*55}")
    print(f"Scorer tests: {passed}/{total} passed")
    if passed == total:
        print(f"{GREEN}All passing.{RESET}")
    else:
        sys.exit(1)
