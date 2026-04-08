"""
tests/test_output.py — tests for output formatters and summary string quality.

Covers:
  - Summary strings contain no non-ASCII characters (backlog fix: em-dash)
  - JSON output is valid and parseable without unicode escapes in summary
  - Terminal, SARIF, GHA, Markdown formatters produce correct structure
  - Delta formatting edge cases
"""

from __future__ import annotations

import json
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from datetime import datetime, timezone, timedelta

from trustwatch.models import ScanResult, GitHubData, BlastRadius
from trustwatch.scorer import score
from trustwatch.output import (
    format_terminal, format_json, format_sarif, format_gha,
    format_markdown, format_results, _fmt_count, _blast_str,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def days_ago(n: int) -> str:
    return (
        datetime.now(timezone.utc) - timedelta(days=n)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_critical() -> dict:
    return {
        "package": "lodash", "ecosystem": "npm", "version": "4.17.21",
        "score": 78, "level": "CRITICAL",
        "summary": ["jdalton controls all releases - no backup if account is compromised",
                    "No activity in 5 years - publish tokens almost certainly stale"],
        "data_source": "registry",
        "delta": {"delta": 38, "trend": "sharply_rising", "previous_score": 40,
                  "previous_level": "MEDIUM", "days_since_last": 14, "history_count": 2},
        "blast_radius": {"dependent_count": 15_000_000, "impact": "critical_infrastructure"},
    }


def make_low() -> dict:
    return {
        "package": "requests", "ecosystem": "pypi", "version": "2.33.1",
        "score": 22, "level": "LOW",
        "summary": ["No significant risk signals detected."],
        "data_source": "github",
        "delta": None,
        "blast_radius": {"dependent_count": 340_000, "impact": "high"},
    }


def make_medium() -> dict:
    return {
        "package": "axios", "ecosystem": "npm", "version": "1.14.0",
        "score": 48, "level": "MEDIUM",
        "summary": ["Two people share publish rights - high concentration"],
        "data_source": "registry",
        "delta": {"delta": -12, "trend": "falling", "previous_score": 60,
                  "previous_level": "HIGH", "days_since_last": 7, "history_count": 3},
        "blast_radius": {"dependent_count": 8_000_000, "impact": "very_high"},
    }


# ── summary string quality ────────────────────────────────────────────────────

class TestSummaryAscii:
    """
    Backlog fix v0.4.6: summary strings must be ASCII-safe.
    Em-dash (U+2014, \\u2014) causes ugly JSON escapes and breaks
    consumers that don't handle unicode properly.
    """

    def _score_raw(self, result: ScanResult) -> list[str]:
        return score(result).summary

    def test_solo_maintainer_no_emdash(self) -> None:
        raw = ScanResult(
            ecosystem="npm", package="lodash", latest_version="4.17.21",
            total_versions=114, maintainers=["jdalton"], maintainer_count=1,
            modified="2021-02-20T00:00:00Z",
        )
        summary = self._score_raw(raw)
        for line in summary:
            assert "\u2014" not in line, (
                f"Em-dash found in summary: {line!r}\n"
                "Use ' - ' instead of ' — '"
            )

    def test_stale_credentials_no_emdash(self) -> None:
        raw = ScanResult(
            ecosystem="npm", package="crypto-js",
            total_versions=50, maintainers=["evanvosberg"], maintainer_count=1,
            modified=days_ago(700),
        )
        summary = self._score_raw(raw)
        for line in summary:
            assert "\u2014" not in line, f"Em-dash in: {line!r}"

    def test_archived_repo_no_emdash(self) -> None:
        gh = GitHubData(
            slug="org/archived", pushed_at=days_ago(800), archived=True,
            recent_commit_authors={}, recent_commit_author_count=0,
            recent_releases=[], recent_release_count=0,
            recent_release_publishers=[], recent_release_publisher_count=0,
            top_contributors=[],
        )
        raw = ScanResult(
            ecosystem="npm", package="archived-pkg",
            maintainers=["user"], maintainer_count=1,
            github=gh, github_slug_found="org/archived",
        )
        summary = self._score_raw(raw)
        for line in summary:
            assert "\u2014" not in line, f"Em-dash in: {line!r}"

    def test_xz_pattern_no_emdash(self) -> None:
        gh = GitHubData(
            slug="owner/xz", pushed_at=days_ago(8),
            recent_commit_authors={"jia-tan": 41, "lasse": 7},
            recent_commit_author_count=2,
            recent_releases=[{"tag": "v5.6.1", "published_at": days_ago(8),
                               "publisher": "jia-tan", "prerelease": False}],
            recent_release_count=1,
            recent_release_publishers=["jia-tan"],
            recent_release_publisher_count=1,
            top_contributors=[{"login": "lasse", "contributions": 1840}],
        )
        raw = ScanResult(
            ecosystem="npm", package="xz-like", total_versions=28,
            maintainers=["lasse"], maintainer_count=1, modified=days_ago(8),
            recent_publisher_count=2,
            recent_publishes=[{"version": "5.6.1", "published_at": days_ago(8),
                               "publisher": "jia-tan"}],
            github=gh,
        )
        summary = self._score_raw(raw)
        for line in summary:
            assert "\u2014" not in line, f"Em-dash in: {line!r}"

    def test_summary_json_no_unicode_escapes(self) -> None:
        """JSON output should not contain \\u2014 escape sequences."""
        raw = ScanResult(
            ecosystem="npm", package="lodash",
            total_versions=114, maintainers=["jdalton"], maintainer_count=1,
            modified="2021-02-20T00:00:00Z",
        )
        report = score(raw)
        json_str = report.to_json()
        assert "\\u2014" not in json_str, (
            "Em-dash unicode escape found in JSON output. "
            "Summary strings must use ASCII ' - ' instead of em-dash."
        )

    def test_all_summary_lines_are_ascii_safe(self) -> None:
        """Every character in every summary line should be < U+0100."""
        scenarios = [
            ScanResult(ecosystem="npm", package="p1",
                       maintainers=["u"], maintainer_count=1,
                       modified="2020-01-01T00:00:00Z"),
            ScanResult(ecosystem="pypi", package="p2",
                       maintainers=[], maintainer_count=0),
            ScanResult(ecosystem="npm", package="p3",
                       maintainers=["a", "b", "c", "d", "e"],
                       maintainer_count=5, modified=days_ago(5)),
        ]
        for raw in scenarios:
            for line in score(raw).summary:
                non_ascii = [c for c in line if ord(c) > 127]
                assert not non_ascii, (
                    f"Non-ASCII chars {non_ascii!r} in summary: {line!r}"
                )


# ── JSON output ───────────────────────────────────────────────────────────────

class TestJsonOutput:
    def test_valid_json(self) -> None:
        out = format_json([make_critical(), make_low()], [], 75)
        parsed = json.loads(out)
        assert "packages" in parsed
        assert "summary" in parsed

    def test_summary_counts_correct(self) -> None:
        results = [make_critical(), make_low(), make_medium()]
        out = format_json(results, [], 75)
        parsed = json.loads(out)
        assert parsed["summary"]["total"]    == 3
        assert parsed["summary"]["critical"] == 1
        assert parsed["summary"]["low"]      == 1
        assert parsed["summary"]["medium"]   == 1

    def test_errors_included(self) -> None:
        errors = [{"package": "broken", "ecosystem": "npm",
                   "error": "network timeout"}]
        out = format_json([make_low()], errors, 75)
        parsed = json.loads(out)
        assert len(parsed["errors"]) == 1
        assert parsed["errors"][0]["package"] == "broken"

    def test_threshold_in_output(self) -> None:
        out = format_json([make_critical()], [], 55)
        assert json.loads(out)["threshold"] == 55

    def test_compact_mode(self) -> None:
        out = format_json([make_critical()], [], 75, indent=None)
        assert "\n" not in out


# ── SARIF output ──────────────────────────────────────────────────────────────

class TestSarifOutput:
    def test_valid_sarif_structure(self) -> None:
        out = format_sarif([make_critical(), make_low()], [], 75)
        sarif = json.loads(out)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert "tool" in sarif["runs"][0]

    def test_only_flagged_packages_in_results(self) -> None:
        """SARIF results only include packages at or above threshold."""
        out = format_sarif([make_critical(), make_low()], [], 75)
        sarif = json.loads(out)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1   # only CRITICAL (78 >= 75), not LOW (22)

    def test_all_included_below_threshold(self) -> None:
        """Lower threshold includes more packages."""
        out = format_sarif([make_critical(), make_low()], [], 10)
        sarif = json.loads(out)
        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_rule_ids_present(self) -> None:
        out = format_sarif([make_critical()], [], 75)
        sarif = json.loads(out)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        assert "id" in rules[0]


# ── GHA output ────────────────────────────────────────────────────────────────

class TestGhaOutput:
    def test_contains_markdown_table(self) -> None:
        out = format_gha([make_critical(), make_low()], [], 75)
        assert "|" in out
        assert "lodash" in out

    def test_contains_level_icons(self) -> None:
        out = format_gha([make_critical(), make_low()], [], 75)
        assert "🔴" in out   # CRITICAL
        assert "🟢" in out   # LOW

    def test_ci_gate_warning_when_triggered(self) -> None:
        out = format_gha([make_critical()], [], 75)
        assert "CI gate" in out or "⚠️" in out

    def test_no_ci_gate_warning_when_clear(self) -> None:
        out = format_gha([make_low()], [], 75)
        assert "CI gate triggered" not in out

    def test_errors_section_present(self) -> None:
        errors = [{"package": "broken", "ecosystem": "npm", "error": "timeout"}]
        out = format_gha([make_low()], errors, 75)
        assert "broken" in out


# ── Markdown output ───────────────────────────────────────────────────────────

class TestMarkdownOutput:
    def test_contains_summary_table(self) -> None:
        out = format_markdown([make_critical(), make_low()], [], 75)
        assert "## Summary" in out
        assert "CRITICAL" in out
        assert "LOW" in out

    def test_flagged_section_for_critical(self) -> None:
        out = format_markdown([make_critical(), make_low()], [], 75)
        assert "Flagged" in out
        assert "lodash" in out

    def test_all_packages_section(self) -> None:
        out = format_markdown([make_critical(), make_low()], [], 75)
        assert "All packages" in out
        assert "requests" in out


# ── Terminal output ───────────────────────────────────────────────────────────

class TestTerminalOutput:
    def test_contains_package_names(self) -> None:
        out = format_terminal([make_critical(), make_low()], [], 75)
        assert "lodash" in out
        assert "requests" in out

    def test_ci_gate_pass(self) -> None:
        out = format_terminal([make_low()], [], 75)
        assert "all packages below threshold" in out.lower()

    def test_ci_gate_fail(self) -> None:
        out = format_terminal([make_critical()], [], 75)
        assert "CI gate" in out
        assert "lodash" in out

    def test_blast_radius_critical_marker(self) -> None:
        out = format_terminal([make_critical()], [], 75)
        assert "◆" in out   # critical_infrastructure marker

    def test_blast_radius_very_high_marker(self) -> None:
        out = format_terminal([make_medium()], [], 75)
        assert "▲" in out   # very_high marker

    def test_legend_shown_when_blast_data_present(self) -> None:
        out = format_terminal([make_critical()], [], 75)
        assert "Dependents:" in out

    def test_delta_rising_shown(self) -> None:
        out = format_terminal([make_critical()], [], 75)
        assert "↑" in out

    def test_delta_falling_shown(self) -> None:
        out = format_terminal([make_medium()], [], 75)
        assert "↓" in out


# ── Blast radius helpers ──────────────────────────────────────────────────────

class TestBlastHelpers:
    def test_fmt_count_millions(self) -> None:
        assert _fmt_count(15_000_000) == "15.0M"
        assert _fmt_count(1_500_000)  == "1.5M"
        assert _fmt_count(1_000_000)  == "1.0M"

    def test_fmt_count_thousands(self) -> None:
        assert _fmt_count(340_000) == "340K"
        assert _fmt_count(10_000)  == "10K"
        assert _fmt_count(1_000)   == "1K"

    def test_fmt_count_small(self) -> None:
        assert _fmt_count(999) == "999"
        assert _fmt_count(0)   == "0"

    def test_blast_str_critical_infra(self) -> None:
        b = _blast_str({"dependent_count": 15_000_000,
                        "impact": "critical_infrastructure"})
        assert "◆" in b
        assert "15.0M" in b

    def test_blast_str_very_high(self) -> None:
        b = _blast_str({"dependent_count": 8_000_000, "impact": "very_high"})
        assert "▲" in b

    def test_blast_str_unknown(self) -> None:
        b = _blast_str({"dependent_count": None, "impact": "unknown"})
        assert "?" in b

    def test_blast_str_none(self) -> None:
        b = _blast_str(None)
        assert "?" in b


# ── run without pytest ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    GREEN = "\033[92m"; RED = "\033[91m"; RESET = "\033[0m"; BOLD = "\033[1m"

    classes = [
        TestSummaryAscii,
        TestJsonOutput, TestSarifOutput,
        TestGhaOutput, TestMarkdownOutput,
        TestTerminalOutput, TestBlastHelpers,
    ]

    total = passed = 0
    for cls in classes:
        print(f"\n{BOLD}{cls.__name__}{RESET}")
        inst = cls()
        methods = sorted(m for m in dir(inst) if m.startswith("test_"))
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
    print(f"Output tests: {passed}/{total} passed")
    if passed == total:
        print(f"{GREEN}All passing.{RESET}")
    else:
        sys.exit(1)
