"""
cli.py — Typer CLI for trustwatch.

Commands:
  scan     — scan one package, print JSON report
  batch    — scan all packages from a manifest file
  history  — show score history and trend for a package
  watch    — continuously monitor packages, alert on changes
  version  — print version string

Design principles:
  - All input validated before any work starts
  - No global state — ScanConfig passed explicitly
  - Logging to stderr, results to stdout
  - Errors exit with code 1, CI gate exits with code 1
  - watch command delivers alerts via webhook (Slack/Discord/generic)
"""

from __future__ import annotations

import json
import logging
import pathlib
import sys
import time
import urllib.error
import urllib.request
from typing import Optional

import typer
from rich.console import Console

from . import __version__
from .constants import (
    CI_GATE_DEFAULT_SCORE, BATCH_PAUSE_SECONDS,
    KNOWN_PYPI, VERSION,
)
from .exceptions import (
    TrustwatchError, ValidationError, ParseError,
    NetworkError, RateLimitError, NotFoundError,
)
from .history import save as history_save, compute_delta, get_history
from .models import ScanConfig, Report, Delta
from .output import format_results, format_terminal
from .parsers import detect_and_parse
from .scanner import scan_package
from .scorer import score
from .validation import (
    validate_package_name, validate_ecosystem, validate_days,
    validate_threshold, validate_output_format, validate_webhook_url,
)

# ── App setup ─────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="trustwatch",
    add_completion=False,
    help=(
        "OSS publish trust scanner. "
        "Find single points of failure before they become incidents."
    ),
)

console = Console(stderr=True)   # status messages → stderr
logger  = logging.getLogger(__name__)


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


# ── Ecosystem auto-detection ──────────────────────────────────────────────────

def _detect_ecosystem(package: str, explicit: str) -> tuple[str, bool]:
    """
    Returns (ecosystem, was_autodetected).
    Only auto-detects when the caller passed the default 'npm'.
    """
    if explicit != "npm":
        return explicit, False
    if "/" in package:
        return "github", True
    if package.lower() in KNOWN_PYPI:
        return "pypi", True
    return "npm", False


# ── Shared scan + record helper ───────────────────────────────────────────────

def _scan_and_record(
    package:   str,
    ecosystem: str,
    cfg:       ScanConfig,
) -> tuple[Report, Delta, "ScanResult"]:
    """
    Scan a package, score it, save to history, compute delta.

    Returns (report, delta, raw_result).
    - Registry failures (npm/PyPI down, package not found) raise and are blocking.
    - GitHub failures are non-blocking: github_error on raw_result, score degrades.
    - History failures are non-blocking: logged, scan result still returned.
    """
    from .models import ScanResult as _SR
    result = scan_package(package, ecosystem, cfg)
    report = score(result)

    try:
        history_save(report)
        delta = compute_delta(package, ecosystem, report.risk.overall_score)
    except Exception as exc:
        logger.warning("History unavailable for %s: %s", package, exc)
        from .models import Delta as DeltaModel
        delta = DeltaModel(
            previous_score=None, previous_level=None,
            delta=None, days_since_last=None,
            trend="unknown", history_count=0,
        )

    report.delta = delta.to_dict()
    return report, delta, result


def _result_entry(report: Report, delta: Delta) -> dict:
    """Convert Report + Delta to the lightweight dict used by formatters."""
    return {
        "package":      report.package,
        "ecosystem":    report.ecosystem,
        "version":      report.latest_version,
        "score":        report.risk.overall_score,
        "level":        report.risk.level,
        "summary":      report.summary,
        "signals":      report.risk.signals.to_dict(),
        "data_source":  report.risk.signals.maintainer_spof.data_source,
        "delta":        delta.to_dict(),
        "blast_radius": report.blast_radius.to_dict() if report.blast_radius else None,
    }


# ── scan command ──────────────────────────────────────────────────────────────

@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def scan(
    ctx: typer.Context,
    ecosystem: str = typer.Option(
        "npm", "--ecosystem", "-e",
        help="npm | pypi | github  (auto-detected when possible)",
    ),
    days: int = typer.Option(
        90, "--days", "-d",
        help="Activity window in days (1–3650)",
    ),
    token: Optional[str] = typer.Option(
        None, "--token", "-t", envvar="GITHUB_TOKEN",
        help="GitHub personal access token (raises rate limit to 5000/hr)",
    ),
    no_github: bool = typer.Option(
        False, "--no-github",
        help="Skip GitHub API calls (use when network blocks api.github.com)",
    ),
    fmt: str = typer.Option(
        "json", "--format", "-f",
        help="Output format: json | sarif | gha | markdown",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Scan a single package and print a trust risk report.

    \b
    Examples:
      trustwatch scan lodash
      trustwatch scan requests                    # auto-detects pypi
      trustwatch scan aquasecurity/trivy          # auto-detects github
      trustwatch scan axios --format sarif
      trustwatch scan core-js --no-github
      trustwatch scan lodash | jq '.risk'
    """
    _setup_logging(verbose)

    # Join positional args — handles org/repo slugs split by shell on Windows
    raw_package = "/".join(ctx.args) if ctx.args else ""
    if not raw_package:
        console.print("[red]Error:[/red] missing package name.")
        console.print("  Example: trustwatch scan lodash")
        raise typer.Exit(code=1)

    # Validate
    try:
        eco_str   = validate_ecosystem(ecosystem)
        eco_final, autodetected = _detect_ecosystem(raw_package, eco_str)
        eco_final = validate_ecosystem(eco_final)
        package   = validate_package_name(raw_package, eco_final)
        days_val  = validate_days(days)
        validate_output_format(fmt)
    except ValidationError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(code=1)

    if autodetected:
        console.print(f"[dim]auto-detected: [bold]{eco_final}[/bold][/dim]")
    if no_github:
        console.print("[dim]GitHub API disabled[/dim]")

    console.print(
        f"[dim]scanning [bold]{package}[/bold] ({eco_final}, {days_val}d)…[/dim]"
    )

    cfg = ScanConfig(days=days_val, token=token, no_github=no_github)

    try:
        report, delta, raw = _scan_and_record(package, eco_final, cfg)
    except RateLimitError as exc:
        # GitHub rate limit — non-blocking if --no-github not set
        console.print(f"[yellow]Rate limit:[/yellow] {exc}")
        console.print("[dim]  Retry with --token or --no-github[/dim]")
        raise typer.Exit(code=1)
    except NotFoundError as exc:
        # Package doesn't exist — blocking
        console.print(f"[red]Not found:[/red] {exc}")
        raise typer.Exit(code=1)
    except NetworkError as exc:
        # Registry unreachable — blocking (can't score without data)
        console.print(f"[red]Network error:[/red] {exc}")
        raise typer.Exit(code=1)
    except TrustwatchError as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=1)

    # Non-blocking: GitHub unavailable — score still valid, just less data
    if raw.github_error and not no_github:
        console.print(
            "[yellow]Warning:[/yellow] GitHub API unavailable — "
            "scores use registry signals only."
        )
        console.print(f"[dim]  {raw.github_error}[/dim]")

    # Delta inline hint
    dv = delta.delta
    if dv is not None and abs(dv) >= 2:
        sign = "+" if dv > 0 else ""
        console.print(
            f"[dim]delta: [bold]{sign}{dv}[/bold] vs last scan "
            f"({delta.days_since_last or '?'}d ago) — {delta.trend}[/dim]"
        )

    # Output
    if fmt == "json":
        indent = 2 if pretty else None
        print(report.to_json(indent=indent or 0))
    else:
        entry = _result_entry(report, delta)
        print(format_results([entry], [], CI_GATE_DEFAULT_SCORE, fmt=fmt))


# ── batch command ─────────────────────────────────────────────────────────────

@app.command()
def batch(
    manifest: str = typer.Argument(
        ..., help="package.json, requirements.txt, or plain .txt watchlist",
    ),
    days: int = typer.Option(90, "--days", "-d"),
    token: Optional[str] = typer.Option(
        None, "--token", "-t", envvar="GITHUB_TOKEN",
    ),
    no_github: bool = typer.Option(False, "--no-github"),
    threshold: int = typer.Option(
        CI_GATE_DEFAULT_SCORE, "--threshold",
        help="Exit code 1 if any package score >= this (CI gate)",
    ),
    fmt: str = typer.Option(
        "terminal", "--format", "-f",
        help="terminal | json | sarif | gha | markdown",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Save output to file",
    ),
    sort_by: str = typer.Option(
        "score", "--sort",
        help="score | name | ecosystem",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Scan all packages in a manifest file.

    \b
    Examples:
      trustwatch batch requirements.txt
      trustwatch batch package.json --threshold 55
      trustwatch batch watchlist.txt --format gha --output summary.md
      trustwatch batch requirements.txt --format sarif --output results.sarif
    """
    _setup_logging(verbose)

    try:
        days_val   = validate_days(days)
        thresh_val = validate_threshold(threshold)
        validate_output_format(fmt)
    except ValidationError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(code=1)

    try:
        entries = detect_and_parse(manifest)
    except FileNotFoundError as exc:
        console.print(f"[red]File not found:[/red] {exc}")
        raise typer.Exit(code=1)
    except ParseError as exc:
        console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(code=1)

    if not entries:
        console.print("[yellow]No packages found in manifest.[/yellow]")
        raise typer.Exit(code=0)

    mname = pathlib.Path(manifest).name
    console.print(f"[dim]found [bold]{len(entries)}[/bold] packages in {mname}[/dim]")

    cfg     = ScanConfig(days=days_val, token=token, no_github=no_github)
    results: list[dict] = []
    errors:  list[dict] = []

    for i, (pkg, eco) in enumerate(entries, 1):
        if eco == "auto":
            eco, _ = _detect_ecosystem(pkg, "npm")
        try:
            eco = validate_ecosystem(eco)
            pkg = validate_package_name(pkg, eco)
        except ValidationError as exc:
            errors.append({"package": pkg, "ecosystem": eco, "error": str(exc)})
            continue

        console.print(
            f"[dim]  [{i}/{len(entries)}] {pkg} ({eco})…[/dim]", end="\r"
        )

        try:
            report, delta, raw = _scan_and_record(pkg, eco, cfg)
            if raw.github_error and not no_github:
                logger.warning(
                    "GitHub unavailable for %s — registry signals only: %s",
                    pkg, raw.github_error,
                )
            results.append(_result_entry(report, delta))
        except (NotFoundError, NetworkError) as exc:
            # Blocking: registry unreachable or package not found
            errors.append({"package": pkg, "ecosystem": eco, "error": str(exc)})
        except TrustwatchError as exc:
            errors.append({"package": pkg, "ecosystem": eco, "error": str(exc)})
        except Exception as exc:
            logger.warning("Unexpected error scanning %s: %s", pkg, exc)
            errors.append({"package": pkg, "ecosystem": eco,
                           "error": f"Unexpected: {exc}"})

        time.sleep(BATCH_PAUSE_SECONDS)

    console.print(" " * 60, end="\r")   # clear progress line

    # Sort
    if sort_by == "name":
        results.sort(key=lambda x: x["package"])
    elif sort_by == "ecosystem":
        results.sort(key=lambda x: (x["ecosystem"], -x["score"]))
    else:
        results.sort(key=lambda x: -x["score"])

    output_str = format_results(results, errors, thresh_val, fmt=fmt)

    if output:
        out_path = pathlib.Path(output)
        out_path.write_text(output_str, encoding="utf-8")
        console.print(f"[dim]Saved to {output}[/dim]")
        # Print terminal summary anyway if saving non-terminal format
        if fmt != "terminal":
            print(format_results(results, errors, thresh_val, fmt="terminal"))
    else:
        print(output_str)

    # CI gate
    if any(r["score"] >= thresh_val for r in results):
        raise typer.Exit(code=1)


# ── history command ───────────────────────────────────────────────────────────

@app.command()
def history(
    package: str = typer.Argument(..., help="Package name"),
    ecosystem: str = typer.Option("npm", "--ecosystem", "-e"),
    limit: int = typer.Option(10, "--limit", "-n"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show scan history and score trend for a package."""
    try:
        eco = validate_ecosystem(ecosystem)
    except ValidationError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(code=1)

    rows = get_history(package, eco, limit=limit)

    if not rows:
        console.print(
            f"[dim]No history for {package} ({eco}). Run a scan first.[/dim]"
        )
        raise typer.Exit(code=0)

    if as_json:
        import dataclasses
        print(json.dumps(
            [dataclasses.asdict(r) for r in rows], indent=2, default=str
        ))
        return

    B, R = "\033[1m", "\033[0m"
    print(f"\n{B}History: {package} ({eco}){R}")
    print("─" * 72)
    print(f"  {'Date':<22} {'Score':>5}  {'Level':<10}  {'Trend':<22}  Top signal")
    print(f"  {'─'*70}")

    prev_score: Optional[int] = None
    for row in reversed(rows):
        date    = row.scanned_at[:16].replace("T", " ")
        sc      = row.score
        lvl     = row.level
        top     = (row.summary[0][:38] + "…"
                   if row.summary and len(row.summary[0]) > 38
                   else (row.summary[0] if row.summary else "—"))
        lvl_clr = _LEVEL_CLR = {
            "CRITICAL": "\033[95m", "HIGH": "\033[91m",
            "MEDIUM": "\033[93m",   "LOW":  "\033[92m",
        }.get(lvl, "")

        if prev_score is not None:
            d = sc - prev_score
            if   d >= 8:  trend = f"\033[91m↑ +{d} sharply rising\033[0m"
            elif d <= -8: trend = f"\033[92m↓ {d} falling\033[0m"
            elif d != 0:  trend = f"\033[93m~ {d:+d} slight change\033[0m"
            else:         trend = f"\033[90m→ stable\033[0m"
        else:
            trend = "\033[90m(first scan)\033[0m"

        print(
            f"  {date:<22} {sc:>5}  "
            f"{lvl_clr}{lvl:<10}\033[0m  {trend:<32}  {top}"
        )
        prev_score = sc

    print(f"  {'─'*70}")
    print(f"  {len(rows)} scans on record\n")


# ── watch command ─────────────────────────────────────────────────────────────

def _send_webhook(url: str, payload: dict) -> bool:
    """
    POST alert payload to a webhook URL.

    Supports Slack incoming webhooks, Discord webhooks, and generic JSON.
    Returns True on success, False on failure (non-fatal).
    """
    if "hooks.slack.com" in url:
        lines = payload.get("alerts", [])
        body: dict = {
            "text": f"*trustwatch alert* — {payload.get('run_label', '')}",
            "attachments": [{"color": "danger", "text": "\n".join(lines),
                             "footer": "trustwatch"}],
        }
    elif "discord.com/api/webhooks" in url:
        body = {
            "content": (
                f"**trustwatch alert** — {payload.get('run_label', '')}\n"
                + "\n".join(payload.get("alerts", []))
            )
        }
    else:
        body = payload

    try:
        data = json.dumps(body).encode("utf-8")
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status < 400
    except Exception as exc:
        logger.warning("Webhook delivery failed to %s: %s", url[:40], exc)
        return False


@app.command()
def watch(
    manifest: str = typer.Argument(
        ..., help="package.json, requirements.txt, or plain .txt watchlist",
    ),
    interval: int = typer.Option(
        24, "--interval", "-i",
        help="Hours between scans",
    ),
    threshold: int = typer.Option(
        CI_GATE_DEFAULT_SCORE, "--threshold",
    ),
    token: Optional[str] = typer.Option(
        None, "--token", "-t", envvar="GITHUB_TOKEN",
    ),
    no_github: bool = typer.Option(False, "--no-github"),
    alert_delta: int = typer.Option(
        15, "--alert-delta",
        help="Alert when score rises by at least this amount",
    ),
    webhook: Optional[str] = typer.Option(
        None, "--webhook", "-w", envvar="TRUSTWATCH_WEBHOOK",
        help="Webhook URL for alerts (Slack/Discord/generic JSON)",
    ),
    fmt: str = typer.Option(
        "terminal", "--format", "-f",
        help="terminal | gha | markdown",
    ),
    output_dir: Optional[str] = typer.Option(
        None, "--output-dir",
        help="Save each run's report to this directory",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Continuously monitor packages, alert when scores change significantly.

    \b
    Examples:
      trustwatch watch watchlist.txt --interval 24
      trustwatch watch package.json --alert-delta 10 --webhook $SLACK_URL
      trustwatch watch requirements.txt --output-dir ./reports
    """
    _setup_logging(verbose)

    try:
        validate_webhook_url(webhook)
        validate_threshold(threshold)
        validate_output_format(fmt)
    except ValidationError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[bold]trustwatch watch[/bold] — every {interval}h")
    console.print(f"  manifest:    {manifest}")
    console.print(f"  threshold:   {threshold}  alert_delta: +{alert_delta}")
    if webhook:
        wh_display = webhook[:40] + "…" if len(webhook) > 40 else webhook
        console.print(f"  webhook:     {wh_display}")
    console.print("  Press Ctrl+C to stop\n")

    run_count = 0

    while True:
        run_count += 1
        ts = time.strftime("%Y-%m-%d %H:%M")
        console.print(f"[dim]── run #{run_count} at {ts} ──[/dim]")

        try:
            entries = detect_and_parse(manifest)
        except (FileNotFoundError, ParseError) as exc:
            console.print(f"[red]Manifest error:[/red] {exc}")
            time.sleep(interval * 3600)
            continue

        cfg     = ScanConfig(days=90, token=token, no_github=no_github)
        results: list[dict] = []
        errors:  list[dict] = []
        alerts:  list[str]  = []

        for pkg, eco in entries:
            if eco == "auto":
                eco, _ = _detect_ecosystem(pkg, "npm")
            try:
                eco = validate_ecosystem(eco)
                pkg = validate_package_name(pkg, eco)
                report, delta, raw = _scan_and_record(pkg, eco, cfg)
                if raw.github_error and not no_github:
                    logger.debug("GitHub unavailable for %s: %s", pkg, raw.github_error)
                entry = _result_entry(report, delta)
                results.append(entry)

                dv = delta.delta
                sc = report.risk.overall_score
                if dv is not None and dv >= alert_delta:
                    alerts.append(
                        f"  ⚠  {pkg} ({eco}): "
                        f"score rose +{dv} "
                        f"({delta.previous_score} → {sc}) — {delta.trend}"
                    )
                elif sc >= threshold:
                    alerts.append(
                        f"  ⚠  {pkg} ({eco}): score {sc}/{report.risk.level} "
                        f"above threshold"
                    )

            except (TrustwatchError, ValidationError) as exc:
                errors.append({"package": pkg, "ecosystem": eco, "error": str(exc)})
            except Exception as exc:
                logger.warning("Unexpected: %s", exc)
                errors.append({"package": pkg, "ecosystem": eco,
                               "error": f"Unexpected: {exc}"})

            time.sleep(BATCH_PAUSE_SECONDS)

        # Alerts
        if alerts:
            console.print("\n[bold red]ALERTS:[/bold red]")
            for a in alerts:
                console.print(a)
            console.print()

            if webhook:
                payload = {
                    "run_label": f"run #{run_count} at {ts}",
                    "manifest":  manifest,
                    "alerts":    alerts,
                    "threshold": threshold,
                    "packages": [
                        {"package": r["package"], "ecosystem": r["ecosystem"],
                         "score": r["score"], "level": r["level"]}
                        for r in results if r["score"] >= threshold
                    ],
                }
                ok = _send_webhook(webhook, payload)
                if ok:
                    console.print("[dim]  webhook delivered[/dim]")

        # Print summary
        results.sort(key=lambda x: -x["score"])
        output_str = format_results(results, errors, threshold, fmt=fmt)
        print(output_str)

        # Save report if output_dir set
        if output_dir:
            out = pathlib.Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            fname = out / f"trustwatch_{time.strftime('%Y%m%d_%H%M')}.md"
            md = format_results(results, errors, threshold, fmt="markdown")
            fname.write_text(md, encoding="utf-8")
            console.print(f"[dim]Report: {fname}[/dim]")

        console.print(
            f"[dim]next scan in {interval}h — Ctrl+C to stop[/dim]\n"
        )
        time.sleep(interval * 3600)


# ── version command ───────────────────────────────────────────────────────────

@app.command()
def version() -> None:
    """Print trustwatch version."""
    print(f"trustwatch {VERSION}")


# ── entrypoint ────────────────────────────────────────────────────────────────

def main() -> None:
    app()
