"""
scorer.py - computes trust risk signals from raw scan data.

Core thesis:
  The metric that predicts compromise is NOT team size.
  It is: "How many humans must collude to ship a malicious release?"
  If the answer is 1 - risk is high regardless of org size.

Design principles:
  - No magic numbers - all thresholds in constants.py
  - All signal functions return typed dataclasses, not raw dicts
  - Explicit logic flow - no hidden side effects
  - Bot filtering applied before any SPOF or new-actor calculation
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from .constants import (
    BOT_PATTERNS, TRUSTED_ORGS, ORG_TRUST_REDUCTION,
    SIGNAL_WEIGHTS, PATTERN_OVERRIDE_FLOOR,
    SCORE_CRITICAL, SCORE_HIGH, SCORE_MEDIUM,
    SUMMARY_SIGNAL_THRESHOLD,
    # Concentration
    CONCENTRATION_UNKNOWN, CONCENTRATION_NONE, CONCENTRATION_SINGLE,
    CONCENTRATION_TWO, CONCENTRATION_SMALL, CONCENTRATION_DISTRIBUTED,
    # SPOF
    SPOF_SOLE_CONTRIBUTOR, SPOF_EXTREME, SPOF_STRONG, SPOF_MODERATE,
    SPOF_DISTRIBUTED, SPOF_REGISTRY_SINGLE, SPOF_REGISTRY_TWO,
    SPOF_REGISTRY_MULTI, SPOF_NO_DATA,
    # Token age
    TOKEN_AGE_VERY_STALE_DAYS, TOKEN_AGE_STALE_DAYS, TOKEN_AGE_MODERATE_DAYS,
    TOKEN_AGE_VERY_STALE_SCORE, TOKEN_AGE_STALE_SCORE, TOKEN_AGE_MODERATE_SCORE,
    TOKEN_AGE_FRESH_SCORE, TOKEN_AGE_UNKNOWN_SCORE,
    # Activity
    ACTIVITY_HIGH_VELOCITY_COUNT, ACTIVITY_HIGH_VELOCITY_SCORE,
    ACTIVITY_NEW_ACTOR_SCORE, ACTIVITY_XZ_PUBLISH_SCORE,
    ACTIVITY_ABANDONMENT_SCORE, ACTIVITY_MIN_VERSIONS_HISTORIC,
    # GitHub health
    GITHUB_ARCHIVED_SCORE, GITHUB_ABANDONED_DAYS, GITHUB_ABANDONED_SCORE,
    GITHUB_LOW_ACTIVITY_DAYS, GITHUB_LOW_ACTIVITY_SCORE,
    GITHUB_OVERWHELMED_ISSUES, GITHUB_OVERWHELMED_SCORE, GITHUB_NO_DATA_SCORE,
    # Pattern thresholds
    XZ_PATTERN_ACTIVITY_MIN, XZ_PATTERN_CONCENTRATION_MIN,
    BURNOUT_CONCENTRATION_MIN, BURNOUT_SPOF_MIN, BURNOUT_TOKEN_AGE_MIN,
    SOLO_SPOF_SCORE_MIN, SOLO_SPOF_HUMAN_COUNT,
    # Blast
    BLAST_CRITICAL_INFRA, BLAST_VERY_HIGH, BLAST_HIGH, BLAST_MEDIUM, BLAST_LOW,
    VERSION,
)
from .models import (
    ScanResult, GitHubData, BlastRadius, RiskAssessment, Signals, Report,
    PublishConcentrationResult, MaintainerSpofResult, TokenAgeResult,
    ActivityDeltaResult, GitHubHealthResult,
)

logger = logging.getLogger(__name__)


# ── Bot helpers ───────────────────────────────────────────────────────────────

def is_bot(login: str) -> bool:
    """Return True if the login matches a known bot pattern."""
    lo = login.lower()
    return any(pat in lo for pat in BOT_PATTERNS)


def filter_bots(authors: dict[str, int]) -> dict[str, int]:
    """Remove bot accounts from a commit author dict."""
    return {k: v for k, v in authors.items() if not is_bot(k)}


# ── Org trust helpers ─────────────────────────────────────────────────────────

def is_trusted_org(result: ScanResult) -> bool:
    """Return True if the package belongs to a known-governance organisation."""
    gh    = result.github
    slug  = (
        (gh.slug if gh else "")
        or result.github_slug_found
        or result.package
    )
    org = slug.split("/")[0].lower() if "/" in slug else ""
    return org in TRUSTED_ORGS


# ── Main entry ────────────────────────────────────────────────────────────────

def score(result: ScanResult, scanned_at: Optional[str] = None) -> Report:
    """
    Score a ScanResult and return a fully typed Report.

    Args:
        result:     Raw scan data from the scanner.
        scanned_at: ISO timestamp - defaults to now (UTC).

    Returns:
        Report with risk assessment, blast radius, and plain-English summary.
    """
    if scanned_at is None:
        scanned_at = datetime.now(timezone.utc).isoformat()

    signals = Signals(
        publish_concentration = _sig_publish_concentration(result),
        maintainer_spof       = _sig_maintainer_spof(result),
        token_age_risk        = _sig_token_age_risk(result),
        activity_delta        = _sig_activity_delta(result),
        github_health         = _sig_github_health(result.github),
    )

    overall, patterns = _compute_overall(signals, result)
    level   = _level_from_score(overall)
    summary = _build_summary(signals)

    blast = result.blast_radius or BlastRadius(
        dependent_count=None, impact="unknown"
    )

    risk = RiskAssessment(
        overall_score      = overall,
        level              = level,
        signals            = signals,
        patterns_triggered = patterns,
    )

    return Report(
        trustwatch     = VERSION,
        scanned_at     = scanned_at,
        package        = result.package,
        ecosystem      = result.ecosystem,
        latest_version = result.latest_version,
        risk           = risk,
        blast_radius   = blast,
        summary        = summary,
    )


# ── Overall score + pattern overrides ────────────────────────────────────────

def _compute_overall(
    signals: Signals, result: ScanResult
) -> tuple[int, list[str]]:
    """
    Compute weighted overall score and detect pattern overrides.

    Returns:
        (overall_score, list_of_triggered_pattern_names)
    """
    sdict = signals.to_dict()
    overall = round(
        sum(
            sdict[k]["score"] * w
            for k, w in SIGNAL_WEIGHTS.items()
        )
    )

    patterns: list[str] = []

    # XZ-Utils infiltration pattern
    if (
        signals.activity_delta.score        >= XZ_PATTERN_ACTIVITY_MIN
        and signals.publish_concentration.score >= XZ_PATTERN_CONCENTRATION_MIN
    ):
        patterns.append("xz_infiltration")

    # Burnout / abandonment pattern
    if (
        signals.publish_concentration.score >= BURNOUT_CONCENTRATION_MIN
        and signals.maintainer_spof.score   >= BURNOUT_SPOF_MIN
        and signals.token_age_risk.score    >= BURNOUT_TOKEN_AGE_MIN
    ):
        patterns.append("burnout_abandonment")

    # Solo SPOF - active solo maintainer is still a single point of failure
    if (
        signals.maintainer_spof.human_author_count == SOLO_SPOF_HUMAN_COUNT
        and signals.maintainer_spof.score          >= SOLO_SPOF_SCORE_MIN
        and not is_trusted_org(result)
    ):
        patterns.append("solo_spof")

    if patterns:
        overall = max(overall, PATTERN_OVERRIDE_FLOOR)

    return overall, patterns


def _level_from_score(score: int) -> str:
    if score >= SCORE_CRITICAL: return "CRITICAL"
    if score >= SCORE_HIGH:     return "HIGH"
    if score >= SCORE_MEDIUM:   return "MEDIUM"
    return "LOW"


def _build_summary(signals: Signals) -> list[str]:
    """
    Build a concise, deduplicated, priority-ordered plain-English summary.

    Rules:
    - One bullet per distinct risk, not one bullet per signal
    - publish_concentration and maintainer_spof often say the same thing -
      collapse them into the most informative version
    - Strip implementation details ("GitHub unavailable", "registry signal")
    - Most alarming finding first
    - Max 4 bullets - beyond that it stops being readable
    """
    pc   = signals.publish_concentration
    spof = signals.maintainer_spof
    tok  = signals.token_age_risk
    act  = signals.activity_delta
    gh   = signals.github_health

    bullets: list[tuple[int, str]] = []   # (priority, text) - lower = more important

    # ── Control concentration ─────────────────────────────────────────────────
    # publish_concentration and maintainer_spof both measure "who is in control"
    # Pick the most informative version - prefer GitHub-sourced (names + share)
    # over registry-sourced, and collapse both into one bullet.
    # Skip entirely if the XZ CRITICAL flag already names the actor - that's more informative.
    xz_actors = set()
    for flag in act.flags:
        if ("CRITICAL" in flag or "infiltration" in flag.lower()) and "XZ" in flag:
            # extract the actor name from the flag if present
            import re as _re
            m = _re.match(r"CRITICAL:\s+(\S+)", flag)
            if m:
                xz_actors.add(m.group(1))

    if pc.score >= SUMMARY_SIGNAL_THRESHOLD or spof.score >= SUMMARY_SIGNAL_THRESHOLD:
        name = spof.top_author or pc.effective_publisher_count

        if spof.data_source == "github" and spof.top_author:
            # Skip if this actor is already named in the XZ flag
            if spof.top_author in xz_actors:
                pass
            else:
                share = f" ({spof.top_author_share_pct}% of commits)" if spof.top_author_share_pct else ""
                if spof.human_author_count == 1:
                    bullets.append((10, f"{spof.top_author} is the only human contributor - sole control of all releases{share}"))
                elif spof.top_author_share_pct and spof.top_author_share_pct >= 70:
                    bullets.append((10, f"{spof.top_author} controls {spof.top_author_share_pct}% of commits and can publish alone"))
                else:
                    bullets.append((10, pc.detail))
        elif spof.data_source == "registry" and spof.top_author:
            # Have a name from registry but no commit data - strip the "(GitHub unavailable)" noise
            count_str = f"1 person ({spof.top_author})" if spof.top_author else "1 person"
            bullets.append((10, f"{count_str} controls all releases - no backup if account is compromised"))
        elif pc.effective_publisher_count == 1:
            bullets.append((10, "Single person can publish alone - no backup if account is compromised"))
        elif pc.effective_publisher_count == 2:
            bullets.append((20, "Only 2 people share publish rights - high concentration"))
        elif pc.score >= SUMMARY_SIGNAL_THRESHOLD:
            bullets.append((20, pc.detail))

    # ── Credential staleness ──────────────────────────────────────────────────
    if tok.score >= SUMMARY_SIGNAL_THRESHOLD and tok.age_days is not None:
        age = tok.age_days
        years = age // 365
        if years >= 2:
            bullets.append((30, f"No activity in {years} years - publish tokens almost certainly stale"))
        elif age > 365:
            bullets.append((30, f"No activity in {age}d - credentials likely stale"))
        else:
            bullets.append((30, tok.detail))
    elif tok.score >= SUMMARY_SIGNAL_THRESHOLD:
        bullets.append((30, tok.detail))

    # ── Activity delta: new actors, XZ pattern ────────────────────────────────
    # First pass: collect names already covered by XZ flags
    import re as _re_act
    xz_named_actors: set[str] = set()
    for flag in act.flags:
        if "CRITICAL" in flag or "infiltration" in flag.lower():
            m = _re_act.match(r"CRITICAL:\s+(\S+)", flag)
            if m:
                xz_named_actors.add(m.group(1))

    xz_flag_added = False
    for flag in act.flags:
        if "No unusual" in flag:
            continue
        if "CRITICAL" in flag or "XZ" in flag or "infiltration" in flag.lower():
            bullets.append((5, flag))
            xz_flag_added = True
        elif "new actor" in flag.lower() or "New actor" in flag:
            # Skip if all actors in this flag are already named in the XZ flag
            flag_actors = set(_re_act.findall(r"commits:\s+(.+)", flag))
            if flag_actors and flag_actors.issubset(xz_named_actors):
                continue
            bullets.append((15, flag))
        elif "velocity" in flag.lower():
            bullets.append((40, flag))
        elif "abandonment" in flag.lower() or "possible" in flag.lower():
            has_staleness = any("stale" in b or "activity" in b or "year" in b
                                for _, b in bullets)
            if not has_staleness:
                bullets.append((35, flag))

    # ── GitHub health: archived, abandoned ───────────────────────────────────
    for flag in gh.flags:
        if "healthy" in flag:
            continue
        if "archived" in flag.lower():
            bullets.append((25, "Repository is archived - officially unmaintained"))
        elif "abandoned" in flag.lower() or "No push" in flag:
            # only if not already covered by token age bullet
            has_staleness = any("year" in b or "stale" in b or "activity" in b
                                for _, b in bullets)
            if not has_staleness:
                bullets.append((35, flag))
        else:
            bullets.append((50, flag))

    if not bullets:
        return ["No significant risk signals detected."]

    # Sort by priority, deduplicate near-identical bullets, cap at 4
    bullets.sort(key=lambda x: x[0])
    seen: list[str] = []
    for _, text in bullets:
        # Skip if very similar to something already in seen
        if not any(_similar(text, s) for s in seen):
            seen.append(text)
        if len(seen) == 4:
            break

    return seen


def _similar(a: str, b: str) -> bool:
    """Return True if two summary bullets are saying the same thing."""
    # Normalise and check for significant word overlap
    wa = set(a.lower().split())
    wb = set(b.lower().split())
    # Remove filler words
    stop = {"the", "a", "an", "is", "are", "of", "in", "to", "and", "or",
            "for", "from", "with", "it", "its", "by", "at", "-", "-"}
    wa -= stop
    wb -= stop
    if not wa or not wb:
        return False
    overlap = len(wa & wb) / min(len(wa), len(wb))
    return overlap > 0.55


# ── Signal functions ──────────────────────────────────────────────────────────

def _sig_publish_concentration(
    result: ScanResult,
) -> PublishConcentrationResult:
    """How many distinct identities can publish a release alone?"""
    trusted  = is_trusted_org(result)
    org_cut  = ORG_TRUST_REDUCTION if trusted else 0
    org_note = " (org-backed - governance reduces risk)" if trusted else ""

    effective: int

    if result.ecosystem == "npm":
        count = result.recent_publisher_count
        mc    = result.maintainer_count
        effective = min(count, mc) if count and mc else (count or mc)

    elif result.ecosystem == "pypi":
        mc = result.maintainer_count
        effective = mc if mc > 0 else -1   # -1 = genuinely unknown

    else:  # github
        gh = result.github
        if gh:
            effective = (
                gh.recent_release_publisher_count
                or gh.recent_commit_author_count
            )
        else:
            effective = 0

    if effective == -1:
        return PublishConcentrationResult(
            score                  = max(0, CONCENTRATION_UNKNOWN - org_cut),
            detail                 = f"Publisher count unavailable via PyPI API - not alarming{org_note}",
            data_source            = "registry",
            effective_publisher_count = None,
            trusted_org            = trusted,
        )
    if effective == 0:
        return PublishConcentrationResult(
            score                  = max(0, CONCENTRATION_NONE - org_cut),
            detail                 = f"No recent publishers detected{org_note}",
            data_source            = "registry",
            effective_publisher_count = 0,
            trusted_org            = trusted,
        )
    if effective == 1:
        return PublishConcentrationResult(
            score                  = max(0, CONCENTRATION_SINGLE - org_cut),
            detail                 = f"Single person can publish alone - critical concentration{org_note}",
            data_source            = "registry",
            effective_publisher_count = 1,
            trusted_org            = trusted,
        )
    if effective == 2:
        return PublishConcentrationResult(
            score                  = max(0, CONCENTRATION_TWO - org_cut),
            detail                 = f"Two people share publish rights - high concentration{org_note}",
            data_source            = "registry",
            effective_publisher_count = 2,
            trusted_org            = trusted,
        )
    if effective <= 4:
        return PublishConcentrationResult(
            score                  = max(0, CONCENTRATION_SMALL - org_cut),
            detail                 = f"{effective} publish identities - moderate concentration{org_note}",
            data_source            = "registry",
            effective_publisher_count = effective,
            trusted_org            = trusted,
        )
    return PublishConcentrationResult(
        score                  = max(0, CONCENTRATION_DISTRIBUTED - org_cut),
        detail                 = f"{effective} publish identities - distributed, lower risk{org_note}",
        data_source            = "registry",
        effective_publisher_count = effective,
        trusted_org            = trusted,
    )


def _sig_maintainer_spof(result: ScanResult) -> MaintainerSpofResult:
    """Does one person dominate the commit and release history?"""
    trusted  = is_trusted_org(result)
    org_cut  = ORG_TRUST_REDUCTION if trusted else 0
    org_note = " (org-backed)" if trusted else ""
    gh       = result.github

    raw_authors    = gh.recent_commit_authors if gh else {}
    commit_authors = filter_bots(raw_authors)
    bots_removed   = len(raw_authors) - len(commit_authors)

    # ── Registry fallback when GitHub unavailable ─────────────────────────
    if not commit_authors:
        count = result.maintainer_count
        names = result.maintainers

        if count == 0:
            return MaintainerSpofResult(
                score              = SPOF_NO_DATA,
                detail             = "No commit or maintainer data available",
                data_source        = "none",
                bots_excluded      = bots_removed,
                human_author_count = None,
            )
        if count == 1:
            name = names[0] if names else "sole maintainer"
            return MaintainerSpofResult(
                score              = max(0, SPOF_REGISTRY_SINGLE - org_cut),
                detail             = f"{name} is the sole registry maintainer - SPOF (GitHub unavailable){org_note}",
                data_source        = "registry",
                top_author         = name,
                human_author_count = 1,
                bots_excluded      = bots_removed,
            )
        if count == 2:
            return MaintainerSpofResult(
                score              = max(0, SPOF_REGISTRY_TWO - org_cut),
                detail             = f"2 registry maintainers - moderate SPOF risk (GitHub unavailable){org_note}",
                data_source        = "registry",
                human_author_count = 2,
                bots_excluded      = bots_removed,
            )
        return MaintainerSpofResult(
            score              = max(0, SPOF_REGISTRY_MULTI - org_cut),
            detail             = f"{count} registry maintainers (GitHub unavailable){org_note}",
            data_source        = "registry",
            human_author_count = count,
            bots_excluded      = bots_removed,
        )

    # ── Full GitHub commit analysis ───────────────────────────────────────
    total       = sum(commit_authors.values()) or 1
    ranked      = sorted(commit_authors.items(), key=lambda x: x[1], reverse=True)
    top_name, top_count = ranked[0]
    share       = round(top_count / total * 100, 1)
    human_count = len(commit_authors)

    if human_count == 1 and share >= 95:
        return MaintainerSpofResult(
            score                 = max(0, SPOF_SOLE_CONTRIBUTOR - org_cut),
            detail                = f"{top_name} is the sole human contributor - extreme SPOF{org_note}",
            data_source           = "github",
            top_author            = top_name,
            top_author_share_pct  = share,
            human_author_count    = human_count,
            bots_excluded         = bots_removed,
        )

    raw_score: int
    detail: str
    if share >= 90:
        raw_score = SPOF_EXTREME
        detail    = f"{top_name} made {share}% of recent commits - extreme SPOF{org_note}"
    elif share >= 70:
        raw_score = SPOF_STRONG
        detail    = f"{top_name} made {share}% of recent commits - strong SPOF{org_note}"
    elif share >= 50:
        raw_score = SPOF_MODERATE
        detail    = f"{top_name} made {share}% of recent commits - moderate concentration{org_note}"
    else:
        raw_score = SPOF_DISTRIBUTED
        detail    = f"Commits well distributed - top human author {top_name} at {share}%{org_note}"

    return MaintainerSpofResult(
        score                = max(0, raw_score - org_cut),
        detail               = detail,
        data_source          = "github",
        top_author           = top_name,
        top_author_share_pct = share,
        human_author_count   = human_count,
        bots_excluded        = bots_removed,
    )


def _sig_token_age_risk(result: ScanResult) -> TokenAgeResult:
    """Proxy for stale long-lived publish credentials."""
    gh           = result.github
    modified_str = result.modified or (gh.pushed_at if gh else "")

    if not modified_str:
        return TokenAgeResult(
            score        = TOKEN_AGE_UNKNOWN_SCORE,
            detail       = "Cannot determine last modified - assume elevated",
            last_modified = None,
            age_days     = None,
        )

    try:
        ts  = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - ts).days
    except ValueError:
        logger.debug("Cannot parse modified date: %s", modified_str)
        return TokenAgeResult(
            score        = TOKEN_AGE_UNKNOWN_SCORE,
            detail       = f"Cannot parse modified date: {modified_str}",
            last_modified = modified_str,
            age_days     = None,
        )

    if age > TOKEN_AGE_VERY_STALE_DAYS:
        return TokenAgeResult(
            score        = TOKEN_AGE_VERY_STALE_SCORE,
            detail       = f"Last modified {age}d ago - tokens likely very stale",
            last_modified = modified_str,
            age_days     = age,
        )
    if age > TOKEN_AGE_STALE_DAYS:
        return TokenAgeResult(
            score        = TOKEN_AGE_STALE_SCORE,
            detail       = f"Last modified {age}d ago - tokens may be stale",
            last_modified = modified_str,
            age_days     = age,
        )
    if age > TOKEN_AGE_MODERATE_DAYS:
        return TokenAgeResult(
            score        = TOKEN_AGE_MODERATE_SCORE,
            detail       = f"Last modified {age}d ago - moderate staleness",
            last_modified = modified_str,
            age_days     = age,
        )
    return TokenAgeResult(
        score        = TOKEN_AGE_FRESH_SCORE,
        detail       = f"Last modified {age}d ago - recently active",
        last_modified = modified_str,
        age_days     = age,
    )


def _sig_activity_delta(result: ScanResult) -> ActivityDeltaResult:
    """Unusual activity patterns: new actors, velocity spikes, abandonment."""
    gh      = result.github
    recent  = result.recent_publishes or (gh.recent_releases if gh else [])
    n       = len(recent)
    total   = result.total_versions
    flags:  list[str] = []
    s       = 0

    if n > ACTIVITY_HIGH_VELOCITY_COUNT:
        s += ACTIVITY_HIGH_VELOCITY_SCORE
        flags.append(f"High publish velocity: {n} releases in window")

    if gh:
        top_contributors  = gh.top_contributors
        recent_authors    = gh.recent_commit_authors
        release_publishers = set(gh.recent_release_publishers)

        if top_contributors and recent_authors:
            human_recent = filter_bots(recent_authors)
            all_time     = {
                c["login"] for c in top_contributors
                if not is_bot(c["login"])
            }
            recent_top   = set(list(human_recent.keys())[:3])
            new_actors   = recent_top - all_time

            if new_actors:
                s += ACTIVITY_NEW_ACTOR_SCORE
                flags.append(
                    f"New actor(s) dominating recent commits: "
                    f"{', '.join(sorted(new_actors))}"
                )
                publishing_new = new_actors & release_publishers
                if publishing_new:
                    s += ACTIVITY_XZ_PUBLISH_SCORE
                    flags.append(
                        f"CRITICAL: {', '.join(sorted(publishing_new))} is new "
                        f"to this project but already publishing releases - "
                        f"matches XZ-Utils infiltration pattern"
                    )

    if total > ACTIVITY_MIN_VERSIONS_HISTORIC and n == 0:
        s += ACTIVITY_ABANDONMENT_SCORE
        flags.append(
            "No recent publishes despite historically active project "
            "- possible abandonment"
        )

    if not flags:
        flags.append("No unusual activity patterns detected")

    return ActivityDeltaResult(
        score                = min(s, 100),
        detail               = flags[0],
        recent_publish_count = n,
        flags                = flags,
    )


def _sig_github_health(
    gh: Optional[GitHubData],
) -> GitHubHealthResult:
    """Repository-level health signals."""
    if gh is None:
        return GitHubHealthResult(
            score       = GITHUB_NO_DATA_SCORE,
            detail      = "No GitHub repo linked",
            flags       = ["No GitHub repo linked"],
        )

    flags: list[str] = []
    s = 0

    if gh.archived:
        s += GITHUB_ARCHIVED_SCORE
        flags.append("Repository is archived - no active maintenance")

    if gh.pushed_at:
        try:
            ts  = datetime.fromisoformat(gh.pushed_at.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - ts).days
            if age > GITHUB_ABANDONED_DAYS:
                s += GITHUB_ABANDONED_SCORE
                flags.append(f"No push in {age}d - likely abandoned")
            elif age > GITHUB_LOW_ACTIVITY_DAYS:
                s += GITHUB_LOW_ACTIVITY_SCORE
                flags.append(f"No push in {age}d - low activity")
        except ValueError:
            logger.debug("Cannot parse pushed_at: %s", gh.pushed_at)

    if gh.open_issues > GITHUB_OVERWHELMED_ISSUES:
        s += GITHUB_OVERWHELMED_SCORE
        flags.append(
            f"{gh.open_issues} open issues - possible maintainer overwhelm"
        )

    if not flags:
        flags.append("GitHub repo appears healthy")

    return GitHubHealthResult(
        score    = min(s, 100),
        detail   = flags[0],
        stars    = gh.stars,
        archived = gh.archived,
        flags    = flags,
    )


# ── Blast radius label ────────────────────────────────────────────────────────

def blast_label(count: Optional[int]) -> str:
    """Map a dependent count to a human-readable impact tier."""
    if count is None:              return "unknown"
    if count >= BLAST_CRITICAL_INFRA: return "critical_infrastructure"
    if count >= BLAST_VERY_HIGH:   return "very_high"
    if count >= BLAST_HIGH:        return "high"
    if count >= BLAST_MEDIUM:      return "medium"
    if count >= BLAST_LOW:         return "low"
    return "minimal"
