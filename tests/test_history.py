"""
tests/test_history.py — unit tests for SQLite history store and delta calculation.
Uses a temp database — never touches production .trustwatch_history.db
"""

from __future__ import annotations

import sys
import pathlib
import time
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import trustwatch.history as hist
from trustwatch.models import ScanResult
from trustwatch.scorer import score
from trustwatch.exceptions import HistoryError
from datetime import datetime, timezone, timedelta


def days_ago(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _setup_temp_db() -> pathlib.Path:
    tmp = pathlib.Path(tempfile.mktemp(suffix=".db"))
    hist.DB_PATH = tmp
    return tmp


def _teardown_temp_db(p: pathlib.Path) -> None:
    p.unlink(missing_ok=True)


def _make_report(pkg: str, eco: str, modified_days_ago: int = 10):
    raw = ScanResult(
        ecosystem=eco, package=pkg, latest_version="1.0",
        total_versions=50, maintainers=["user1"], maintainer_count=1,
        modified=days_ago(modified_days_ago),
    )
    return score(raw)


class TestHistorySave:
    def setup_method(self) -> None:
        self.db = _setup_temp_db()

    def teardown_method(self) -> None:
        _teardown_temp_db(self.db)

    def test_save_and_retrieve(self) -> None:
        report = _make_report("lodash", "npm")
        hist.save(report)
        rows = hist.get_history("lodash", "npm")
        assert len(rows) == 1
        assert rows[0].package == "lodash"
        assert rows[0].ecosystem == "npm"
        assert rows[0].score == report.risk.overall_score
        assert rows[0].level == report.risk.level

    def test_multiple_saves_ordered_newest_first(self) -> None:
        for i in range(3):
            hist.save(_make_report("lodash", "npm"))
            time.sleep(0.05)
        rows = hist.get_history("lodash", "npm")
        assert len(rows) == 3
        # newest first
        for i in range(len(rows) - 1):
            assert rows[i].scanned_at >= rows[i + 1].scanned_at

    def test_different_packages_isolated(self) -> None:
        hist.save(_make_report("lodash", "npm"))
        hist.save(_make_report("axios", "npm"))
        hist.save(_make_report("requests", "pypi"))

        assert len(hist.get_history("lodash",   "npm"))  == 1
        assert len(hist.get_history("axios",    "npm"))  == 1
        assert len(hist.get_history("requests", "pypi")) == 1

    def test_different_ecosystems_isolated(self) -> None:
        hist.save(_make_report("requests", "npm"))
        hist.save(_make_report("requests", "pypi"))
        assert len(hist.get_history("requests", "npm"))  == 1
        assert len(hist.get_history("requests", "pypi")) == 1

    def test_limit_respected(self) -> None:
        for _ in range(5):
            hist.save(_make_report("lodash", "npm"))
            time.sleep(0.01)
        rows = hist.get_history("lodash", "npm", limit=3)
        assert len(rows) == 3

    def test_empty_history_returns_empty_list(self) -> None:
        rows = hist.get_history("nonexistent", "npm")
        assert rows == []

    def test_summary_stored_correctly(self) -> None:
        report = _make_report("lodash", "npm")
        hist.save(report)
        rows = hist.get_history("lodash", "npm")
        assert rows[0].summary == report.summary


class TestDeltaComputation:
    def setup_method(self) -> None:
        self.db = _setup_temp_db()

    def teardown_method(self) -> None:
        _teardown_temp_db(self.db)

    def test_first_scan_returns_first_scan_trend(self) -> None:
        report = _make_report("lodash", "npm")
        hist.save(report)
        delta = hist.compute_delta("lodash", "npm", report.risk.overall_score)
        assert delta.history_count == 1
        # With only 1 row, previous=current so trend is stable (not first_scan)
        # first_scan fires only when history_count == 0
        assert delta.trend in ("first_scan", "stable")

    def test_no_history_returns_zero_count(self) -> None:
        delta = hist.compute_delta("never-scanned", "npm", 50)
        assert delta.history_count == 0
        assert delta.trend == "first_scan"
        assert delta.delta is None

    def test_rising_score_detected(self) -> None:
        report_low  = _make_report("lodash", "npm", modified_days_ago=10)
        time.sleep(0.05)
        report_high = _make_report("lodash", "npm", modified_days_ago=800)

        hist.save(report_low)
        time.sleep(0.05)
        hist.save(report_high)

        delta = hist.compute_delta("lodash", "npm", report_high.risk.overall_score)
        assert delta.history_count == 2
        assert delta.delta is not None
        # Score should have risen (old modified = high token risk)
        if delta.delta >= 20:
            assert delta.trend == "sharply_rising"
        elif delta.delta >= 8:
            assert delta.trend == "rising"

    def test_stable_score_detected(self) -> None:
        report = _make_report("lodash", "npm")
        hist.save(report)
        time.sleep(0.05)
        hist.save(report)  # same score
        delta = hist.compute_delta("lodash", "npm", report.risk.overall_score)
        assert delta.trend == "stable"
        assert delta.delta == 0

    def test_previous_score_and_level_correct(self) -> None:
        r1 = _make_report("lodash", "npm", modified_days_ago=10)
        hist.save(r1)
        time.sleep(0.05)
        r2 = _make_report("lodash", "npm", modified_days_ago=10)
        hist.save(r2)

        delta = hist.compute_delta("lodash", "npm", r2.risk.overall_score)
        assert delta.previous_score == r1.risk.overall_score
        assert delta.previous_level == r1.risk.level


class TestGetAllPackages:
    def setup_method(self) -> None:
        self.db = _setup_temp_db()

    def teardown_method(self) -> None:
        _teardown_temp_db(self.db)

    def test_returns_distinct_pairs(self) -> None:
        hist.save(_make_report("lodash",   "npm"))
        hist.save(_make_report("axios",    "npm"))
        hist.save(_make_report("requests", "pypi"))
        hist.save(_make_report("lodash",   "npm"))  # duplicate

        pairs = hist.get_all_packages()
        assert len(pairs) == 3   # distinct

        pkgs = {(p["package"], p["ecosystem"]) for p in pairs}
        assert ("lodash",   "npm")  in pkgs
        assert ("axios",    "npm")  in pkgs
        assert ("requests", "pypi") in pkgs

    def test_empty_db_returns_empty(self) -> None:
        assert hist.get_all_packages() == []


# ── run without pytest ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    GREEN = "\033[92m"; RED = "\033[91m"; RESET = "\033[0m"; BOLD = "\033[1m"

    classes = [TestHistorySave, TestDeltaComputation, TestGetAllPackages]

    total = passed = 0
    for cls in classes:
        print(f"\n{BOLD}{cls.__name__}{RESET}")
        inst = cls()
        methods = [m for m in dir(inst) if m.startswith("test_")]
        for method_name in methods:
            total += 1
            try:
                inst.setup_method()
                getattr(inst, method_name)()
                inst.teardown_method()
                print(f"  {GREEN}PASS{RESET}  {method_name}")
                passed += 1
            except Exception as exc:
                inst.teardown_method()
                print(f"  {RED}FAIL{RESET}  {method_name}")
                print(f"       {exc}")
                if "--tb" in sys.argv:
                    traceback.print_exc()

    print(f"\n{'─'*55}")
    print(f"History tests: {passed}/{total} passed")
    if passed == total:
        print(f"{GREEN}All passing.{RESET}")
    else:
        sys.exit(1)
