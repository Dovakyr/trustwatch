"""
history.py — SQLite-backed scan history.

Every scan is saved automatically. On subsequent scans the delta
vs the previous score is computed and attached to the report.

DB location: .trustwatch_history.db in the current working directory.
"""

from __future__ import annotations

import json
import logging
import pathlib
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from .constants import (
    TREND_SHARP_DELTA, TREND_NORMAL_DELTA, TREND_SLIGHT_DELTA,
    HISTORY_DEFAULT_LIMIT,
)
from .exceptions import HistoryError
from .models import Report, Delta, HistoryRecord

logger = logging.getLogger(__name__)

DB_PATH = pathlib.Path.cwd() / ".trustwatch_history.db"

_CREATE_TABLE = """
    CREATE TABLE IF NOT EXISTS scans (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        package      TEXT    NOT NULL,
        ecosystem    TEXT    NOT NULL,
        scanned_at   TEXT    NOT NULL,
        score        INTEGER NOT NULL,
        level        TEXT    NOT NULL,
        summary      TEXT,
        signals_json TEXT
    )
"""

_CREATE_INDEX = """
    CREATE INDEX IF NOT EXISTS idx_pkg_eco
    ON scans(package, ecosystem, scanned_at)
"""


# ── Connection ────────────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute(_CREATE_TABLE)
    conn.execute(_CREATE_INDEX)
    conn.commit()
    return conn


# ── Write ─────────────────────────────────────────────────────────────────────

def save(report: Report) -> None:
    """
    Save a scan report to history.

    Called automatically after every scan.
    Failure is logged but never raised — history is best-effort.

    Args:
        report: Scored report to persist.
    """
    try:
        conn = _connect()
        conn.execute(
            """INSERT INTO scans
               (package, ecosystem, scanned_at, score, level, summary, signals_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                report.package,
                report.ecosystem,
                report.scanned_at,
                report.risk.overall_score,
                report.risk.level,
                json.dumps(report.summary, default=str),
                json.dumps(
                    {k: {"score": v["score"]}
                     for k, v in report.risk.signals.to_dict().items()},
                    default=str,
                ),
            ),
        )
        conn.commit()
        conn.close()
        logger.debug(
            "Saved history: %s (%s) score=%d",
            report.package, report.ecosystem, report.risk.overall_score,
        )
    except sqlite3.Error as exc:
        logger.warning("Failed to save history for %s: %s", report.package, exc)


# ── Read ──────────────────────────────────────────────────────────────────────

def get_history(
    package: str,
    ecosystem: str,
    limit: int = HISTORY_DEFAULT_LIMIT,
) -> list[HistoryRecord]:
    """
    Return last N scans for a package, newest first.

    Args:
        package:   Package name.
        ecosystem: Ecosystem (npm | pypi | github).
        limit:     Maximum number of records to return.

    Returns:
        List of HistoryRecord, empty list if no history.

    Raises:
        HistoryError: If the database cannot be read.
    """
    try:
        conn = _connect()
        rows = conn.execute(
            """SELECT * FROM scans
               WHERE package = ? AND ecosystem = ?
               ORDER BY scanned_at DESC
               LIMIT ?""",
            (package, ecosystem, limit),
        ).fetchall()
        conn.close()
        return [
            HistoryRecord(
                id         = row["id"],
                package    = row["package"],
                ecosystem  = row["ecosystem"],
                scanned_at = row["scanned_at"],
                score      = row["score"],
                level      = row["level"],
                summary    = json.loads(row["summary"] or "[]"),
                signals    = json.loads(row["signals_json"] or "{}"),
            )
            for row in rows
        ]
    except sqlite3.Error as exc:
        raise HistoryError(f"Cannot read history: {exc}") from exc


def get_all_packages() -> list[dict]:
    """Return all (package, ecosystem) pairs that have history."""
    try:
        conn = _connect()
        rows = conn.execute(
            "SELECT DISTINCT package, ecosystem FROM scans ORDER BY package, ecosystem"
        ).fetchall()
        conn.close()
        return [{"package": r["package"], "ecosystem": r["ecosystem"]} for r in rows]
    except sqlite3.Error as exc:
        raise HistoryError(f"Cannot list packages: {exc}") from exc


# ── Delta ─────────────────────────────────────────────────────────────────────

def compute_delta(
    package: str,
    ecosystem: str,
    current_score: int,
) -> Delta:
    """
    Compare current score against history.

    Returns Delta. If no prior history exists, delta is None and
    trend is "first_scan".
    """
    try:
        rows = get_history(package, ecosystem, limit=2)
    except HistoryError as exc:
        logger.warning("Cannot compute delta for %s: %s", package, exc)
        return Delta(
            previous_score  = None,
            previous_level  = None,
            delta           = None,
            days_since_last = None,
            trend           = "unknown",
            history_count   = 0,
        )

    if len(rows) < 2:
        if len(rows) == 1:
            prev  = rows[0]
            delta = current_score - prev.score
            try:
                prev_dt    = datetime.fromisoformat(prev.scanned_at)
                days_since = (datetime.now(timezone.utc) - prev_dt).days
            except ValueError:
                days_since = None
            return Delta(
                previous_score  = prev.score,
                previous_level  = prev.level,
                delta           = delta,
                days_since_last = days_since,
                trend           = _trend_label(delta),
                history_count   = 1,
            )
        return Delta(
            previous_score  = None,
            previous_level  = None,
            delta           = None,
            days_since_last = None,
            trend           = "first_scan",
            history_count   = 0,
        )

    # rows[0] = current (just saved), rows[1] = previous
    prev  = rows[1]
    delta = current_score - prev.score

    try:
        prev_dt    = datetime.fromisoformat(prev.scanned_at)
        days_since = (datetime.now(timezone.utc) - prev_dt).days
    except ValueError:
        days_since = None

    return Delta(
        previous_score  = prev.score,
        previous_level  = prev.level,
        delta           = delta,
        days_since_last = days_since,
        trend           = _trend_label(delta),
        history_count   = len(get_history(package, ecosystem, limit=10000)),
    )


def _trend_label(delta: int) -> str:
    if delta   >= TREND_SHARP_DELTA:   return "sharply_rising"
    if delta   >= TREND_NORMAL_DELTA:  return "rising"
    if delta   >= TREND_SLIGHT_DELTA:  return "slightly_rising"
    if delta   <= -TREND_SHARP_DELTA:  return "sharply_falling"
    if delta   <= -TREND_NORMAL_DELTA: return "falling"
    if delta   <= -TREND_SLIGHT_DELTA: return "slightly_falling"
    return "stable"
