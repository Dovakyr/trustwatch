"""
output.py — output formatters for trustwatch results.

Supported formats:
  terminal    Colour table with delta and blast radius (default for humans)
  json        Machine-readable, full Report structure
  sarif       SARIF 2.1.0 for GitHub Security tab
  gha         GitHub Actions step summary markdown
  markdown    Standalone report

All formatters take a list of result dicts (lightweight, not full Report)
plus errors and threshold. Full Report JSON serialisation uses Report.to_json().
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from .constants import (
    BLAST_CRITICAL_INFRA, BLAST_VERY_HIGH, BLAST_HIGH, BLAST_MEDIUM,
    VERSION,
)

logger = logging.getLogger(__name__)


# ── Result dict shape (lightweight, for batch/watch display) ──────────────────
#
# {
#   package:     str
#   ecosystem:   str
#   version:     str
#   score:       int
#   level:       str      LOW | MEDIUM | HIGH | CRITICAL
#   summary:     list[str]
#   data_source: str
#   delta:       dict | None
#   blast_radius: dict | None
# }


# ── ANSI palette ──────────────────────────────────────────────────────────────

_LEVEL_CLR = {
    "CRITICAL": "\033[95m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[92m",
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_DIM   = "\033[90m"


def _clr(text: str, level: str) -> str:
    return f"{_LEVEL_CLR.get(level, '')}{text}{_RESET}"


def _level_icon(level: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "")


# ── Delta formatting ──────────────────────────────────────────────────────────

def _delta_str(d: Optional[dict], colour: bool = True) -> str:
    """Format delta value for display."""
    if not d:
        return "  new"
    dv = d.get("delta")
    if dv is None:
        return "  new"
    if colour:
        if dv >= 8:    return f"\033[91m+{dv:>3}↑{_RESET}"
        if dv <= -8:   return f"\033[92m{dv:>4}↓{_RESET}"
        if dv != 0:    return f"\033[93m{dv:>+3}~{_RESET}"
    else:
        if dv >= 8:    return f"+{dv}↑"
        if dv <= -8:   return f"{dv}↓"
        if dv != 0:    return f"{dv:+d}~"
    return "   →"


def _delta_str_md(d: Optional[dict]) -> str:
    """Format delta for markdown/GHA (no ANSI)."""
    if not d:
        return "new"
    dv = d.get("delta")
    if dv is None:     return "new"
    if dv >= 8:        return f"⬆️ +{dv}"
    if dv <= -8:       return f"⬇️ {dv}"
    if dv != 0:        return f"↕️ {dv:+d}"
    return "→"


# ── Blast radius formatting ───────────────────────────────────────────────────

_BLAST_CLR = {
    "critical_infrastructure": "\033[95m",
    "very_high":               "\033[91m",
    "high":                    "\033[93m",
    "medium":                  "\033[33m",
    "low":                     "\033[90m",
    "minimal":                 "\033[90m",
    "unknown":                 "\033[90m",
}


def _fmt_count(n: int) -> str:
    """Format large numbers compactly: 5_200_000 → 5.2M"""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.0f}K"
    return str(n)


def _blast_str(blast: Optional[dict]) -> str:
    """Coloured blast radius column value for terminal output."""
    if not blast:
        return f"{_DIM}{'?':>9}{_RESET}"
    impact = blast.get("impact", "unknown")
    count  = blast.get("dependent_count")
    colour = _BLAST_CLR.get(impact, _DIM)

    if count is None:
        return f"{colour}{'?':>9}{_RESET}"

    label = _fmt_count(count)
    if impact == "critical_infrastructure":
        label = f"{label} ◆"
    elif impact == "very_high":
        label = f"{label} ▲"

    return f"{colour}{label:>9}{_RESET}"


def _blast_str_plain(blast: Optional[dict]) -> str:
    """Plain blast radius for markdown."""
    if not blast:
        return "?"
    count = blast.get("dependent_count")
    return _fmt_count(count) if count is not None else "?"


# ── Terminal formatter ────────────────────────────────────────────────────────

def format_terminal(
    results: list[dict],
    errors:  list[dict],
    threshold: int,
) -> str:
    B, R, D = _BOLD, _RESET, _DIM
    lines: list[str] = []

    header = (
        f"\n{B}{'Package':<32} {'Eco':<7} {'Score':>5}  {'Delta':>5}  "
        f"{'Level':<10}  {'Dependents':>10}  {'Src':<4}  Top signal{R}"
    )
    sep = "─" * 112
    lines.append(header)
    lines.append(sep)

    for r in results:
        top   = r["summary"][0] if r["summary"] else "—"
        top   = (top[:40] + "…") if len(top) > 41 else top
        lvl   = _clr(f"{r['level']:<10}", r["level"])
        dstr  = _delta_str(r.get("delta"))
        bstr  = _blast_str(r.get("blast_radius"))
        src   = (r.get("data_source") or "?")[:4]
        lines.append(
            f"{r['package']:<32} {r['ecosystem']:<7} {r['score']:>5}  "
            f"{dstr:<5}  {lvl}  {bstr}  {src:<4}  {top}"
        )

    lines.append(sep)

    # Level summary
    by_level: dict[str, int] = {}
    for r in results:
        by_level[r["level"]] = by_level.get(r["level"], 0) + 1

    parts = [
        _clr(f"{by_level[lvl]} {lvl}", lvl)
        for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if by_level.get(lvl)
    ]
    summary_line = f"\n  {len(results)} scanned   " + "   ".join(parts)
    if errors:
        summary_line += f"   {D}{len(errors)} errors{R}"
    lines.append(summary_line)

    # Blast legend when data is present
    has_blast = any(
        (r.get("blast_radius") or {}).get("dependent_count") is not None
        for r in results
    )
    if has_blast:
        lines.append(
            f"  {D}Dependents: ◆ critical infra (10M+)  "
            f"▲ very high (1M+)  high (100K+)  medium (10K+){R}"
        )

    # Errors
    if errors:
        lines.append(f"\n  {D}Errors:{R}")
        for e in errors:
            lines.append(f"    ✗ {e['package']} ({e['ecosystem']}): {e['error']}")

    # CI gate
    criticals = [r for r in results if r["score"] >= threshold]
    if criticals:
        lines.append(
            f"\n  \033[91mCI gate: {len(criticals)} package(s) "
            f"at or above threshold ({threshold})\033[0m"
        )
        for r in criticals:
            lines.append(
                f"    \033[91m✗\033[0m {r['package']} ({r['ecosystem']}): "
                f"{r['score']}/{r['level']}"
            )
    else:
        lines.append(
            f"\n  \033[92mCI gate: all packages below threshold ({threshold})\033[0m"
        )

    return "\n".join(lines)


# ── JSON formatter ────────────────────────────────────────────────────────────

def format_json(
    results:   list[dict],
    errors:    list[dict],
    threshold: int,
    indent:    int | None = 2,
) -> str:
    out = {
        "trustwatch":   VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "threshold":    threshold,
        "summary": {
            "total":    len(results),
            "critical": sum(1 for r in results if r["level"] == "CRITICAL"),
            "high":     sum(1 for r in results if r["level"] == "HIGH"),
            "medium":   sum(1 for r in results if r["level"] == "MEDIUM"),
            "low":      sum(1 for r in results if r["level"] == "LOW"),
            "errors":   len(errors),
        },
        "packages": [
            {
                "package":      r["package"],
                "ecosystem":    r["ecosystem"],
                "version":      r.get("version", ""),
                "score":        r["score"],
                "level":        r["level"],
                "delta":        r.get("delta"),
                "blast_radius": r.get("blast_radius"),
                "summary":      r["summary"],
            }
            for r in results
        ],
        "errors": errors,
    }
    return json.dumps(out, indent=indent, default=str)


# ── SARIF 2.1.0 ───────────────────────────────────────────────────────────────

_SARIF_SEVERITY = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
}


def format_sarif(
    results:   list[dict],
    errors:    list[dict],
    threshold: int,
) -> str:
    """
    SARIF 2.1.0 output.
    Upload to GitHub Security tab via github/codeql-action/upload-sarif.
    Only includes packages at or above threshold.
    """
    rules: list[dict] = []
    seen_rules: set[str] = set()

    for r in results:
        rule_id = f"TW-{r['level']}-{r['ecosystem'].upper()}"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id":   rule_id,
                "name": f"TrustwatchRisk{r['level'].title()}",
                "shortDescription": {"text": f"Publish trust risk: {r['level']}"},
                "fullDescription": {
                    "text": (
                        "trustwatch detected elevated publish trust risk. "
                        "The minimum number of humans needed to ship a malicious "
                        "release may be dangerously low."
                    )
                },
                "helpUri": "https://github.com/trustwatch/trustwatch",
                "properties": {
                    "tags":             ["supply-chain", "trust", r["ecosystem"]],
                    "precision":        "medium",
                    "problem.severity": _SARIF_SEVERITY.get(r["level"], "note"),
                },
            })

    sarif_results: list[dict] = []
    for r in results:
        if r["score"] < threshold:
            continue
        rule_id = f"TW-{r['level']}-{r['ecosystem'].upper()}"
        sarif_results.append({
            "ruleId": rule_id,
            "level":  _SARIF_SEVERITY.get(r["level"], "note"),
            "message": {"text": " ".join(r["summary"])},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"{r['ecosystem']}:{r['package']}"
                        }
                    },
                    "logicalLocations": [
                        {"name": r["package"], "kind": "package"}
                    ],
                }
            ],
            "properties": {
                "score":     r["score"],
                "level":     r["level"],
                "ecosystem": r["ecosystem"],
                "version":   r.get("version", ""),
                "delta":     (r.get("delta") or {}).get("delta"),
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":           "trustwatch",
                        "version":        VERSION,
                        "informationUri": "https://github.com/trustwatch/trustwatch",
                        "rules":          rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)


# ── GitHub Actions step summary ───────────────────────────────────────────────

def format_gha(
    results:   list[dict],
    errors:    list[dict],
    threshold: int,
) -> str:
    """
    Markdown for GitHub Actions $GITHUB_STEP_SUMMARY.
    Renders as a formatted table in the Actions UI.
    """
    lines: list[str] = ["## trustwatch — Supply Chain Trust Report\n"]

    crit = sum(1 for r in results if r["level"] == "CRITICAL")
    high = sum(1 for r in results if r["level"] == "HIGH")
    med  = sum(1 for r in results if r["level"] == "MEDIUM")
    low  = sum(1 for r in results if r["level"] == "LOW")

    lines.append(
        f"**{len(results)} packages scanned** — "
        f"🔴 {crit} CRITICAL · 🟠 {high} HIGH · "
        f"🟡 {med} MEDIUM · 🟢 {low} LOW\n"
    )

    flagged = [r for r in results if r["score"] >= threshold]
    if flagged:
        lines.append(
            f"> ⚠️ **CI gate triggered** — "
            f"{len(flagged)} package(s) at or above threshold ({threshold})\n"
        )

    lines.append(
        "| Package | Eco | Score | Level | Delta | Dependents | Top signal |"
    )
    lines.append("|---|---|---|---|---|---|---|")

    for r in results:
        top   = r["summary"][0] if r["summary"] else "—"
        top   = (top[:50] + "…") if len(top) > 50 else top
        icon  = _level_icon(r["level"])
        dstr  = _delta_str_md(r.get("delta"))
        blast = r.get("blast_radius") or {}
        dep_s = _blast_str_plain(blast)
        lines.append(
            f"| `{r['package']}` | {r['ecosystem']} | {r['score']} | "
            f"{icon} {r['level']} | {dstr} | {dep_s} | {top} |"
        )

    if errors:
        lines.append(f"\n### Errors\n")
        for e in errors:
            lines.append(f"- `{e['package']}` ({e['ecosystem']}): {e['error']}")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(
        f"\n_Generated by [trustwatch](https://github.com/trustwatch/trustwatch) "
        f"at {ts}_"
    )

    return "\n".join(lines)


# ── Markdown report ───────────────────────────────────────────────────────────

def format_markdown(
    results:   list[dict],
    errors:    list[dict],
    threshold: int,
) -> str:
    """Standalone markdown report for documentation or sharing."""
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# trustwatch — Supply Chain Trust Report\n",
        f"Generated: {ts}  \n",
        f"Threshold: {threshold}\n",
        "\n## Summary\n",
        "| Level | Count |",
        "|---|---|",
    ]
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        cnt = sum(1 for r in results if r["level"] == lvl)
        lines.append(f"| {_level_icon(lvl)} {lvl} | {cnt} |")

    flagged = [r for r in results if r["score"] >= threshold]
    if flagged:
        lines += [
            "\n## Flagged packages\n",
            "| Package | Ecosystem | Score | Level | Dependents | Top signal |",
            "|---|---|---|---|---|---|",
        ]
        for r in flagged:
            top   = r["summary"][0] if r["summary"] else "—"
            blast = r.get("blast_radius") or {}
            dep_s = _blast_str_plain(blast)
            lines.append(
                f"| `{r['package']}` | {r['ecosystem']} | **{r['score']}** | "
                f"**{r['level']}** | {dep_s} | {top} |"
            )

    lines += [
        "\n## All packages\n",
        "| Package | Ecosystem | Version | Score | Level | Dependents |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        blast = r.get("blast_radius") or {}
        dep_s = _blast_str_plain(blast)
        lines.append(
            f"| `{r['package']}` | {r['ecosystem']} | {r.get('version','?')} | "
            f"{r['score']} | {_level_icon(r['level'])} {r['level']} | {dep_s} |"
        )

    # Signal detail for flagged packages
    if flagged:
        lines.append("\n## Signal detail\n")
        for r in flagged:
            lines.append(f"### `{r['package']}` ({r['ecosystem']})\n")
            lines.append(f"**Score:** {r['score']} / {r['level']}\n")
            lines.append("**Signals:**\n")
            for point in r["summary"]:
                lines.append(f"- {point}")
            d = r.get("delta") or {}
            if d.get("delta") is not None:
                lines.append(
                    f"\n**Trend:** {d['delta']:+d} vs previous scan "
                    f"({d.get('days_since_last', '?')}d ago) — {d.get('trend', '?')}\n"
                )

    if errors:
        lines.append("\n## Errors\n")
        for e in errors:
            lines.append(f"- `{e['package']}` ({e['ecosystem']}): {e['error']}")

    return "\n".join(lines)


# ── Router ────────────────────────────────────────────────────────────────────

def format_results(
    results:   list[dict],
    errors:    list[dict],
    threshold: int,
    fmt:       str = "terminal",
    indent:    int = 2,
) -> str:
    """
    Route to the appropriate formatter.

    Args:
        results:   List of result dicts (from batch/watch).
        errors:    List of error dicts.
        threshold: CI gate score threshold.
        fmt:       Output format: terminal | json | sarif | gha | markdown.
        indent:    JSON indent level.

    Returns:
        Formatted string ready to write to stdout or file.
    """
    if fmt == "json":
        return format_json(results, errors, threshold, indent=indent)
    if fmt == "sarif":
        return format_sarif(results, errors, threshold)
    if fmt == "gha":
        return format_gha(results, errors, threshold)
    if fmt == "markdown":
        return format_markdown(results, errors, threshold)
    return format_terminal(results, errors, threshold)
