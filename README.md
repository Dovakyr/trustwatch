# trustwatch

**OSS publish trust scanner.**  
Find single points of failure in your software supply chain before they become incidents.

---

## The problem

Every major OSS supply chain attack in 2024–2026 — XZ Utils, axios, Trivy, LiteLLM, ESLint — shared one property: **a single human account was the only thing standing between an attacker and a malicious release.**

Existing tools (Snyk, Dependabot, Scorecard) scan *code*. They miss the human layer.

trustwatch measures the **minimum number of humans that need to be compromised, coerced, or burned out for a malicious release to ship.** If the answer is 1 — risk is high regardless of team size.

---

## Install

```bash
pip install typer rich
pip install -e .
```

Requires Python 3.11+. No other dependencies — uses stdlib `urllib` and `sqlite3`.

---

## Quick start

```bash
# scan one package
trustwatch scan lodash

# scan your Python deps
trustwatch batch requirements.txt

# scan your JS deps
trustwatch batch package.json

# view score history
trustwatch history lodash

# monitor continuously
trustwatch watch watchlist.txt --interval 24
```

---

## Commands

### `scan` — single package

```bash
trustwatch scan <package> [options]

Options:
  -e, --ecosystem    npm | pypi | github  (auto-detected if omitted)
  -d, --days         Activity window in days (default: 90)
  -t, --token        GitHub personal access token (or GITHUB_TOKEN env var)
  --no-github        Skip GitHub API calls (use if network blocked)
  -f, --format       json | sarif | gha | markdown  (default: json)
  --pretty/--compact JSON indentation (default: pretty)
```

**Ecosystem auto-detection:**
- `org/repo` slugs → `github`
- Known PyPI packages (requests, boto3, numpy, etc.) → `pypi`
- Everything else → `npm`

**Examples:**
```bash
trustwatch scan lodash
trustwatch scan requests                        # auto-detects pypi
trustwatch scan aquasecurity/trivy              # auto-detects github
trustwatch scan axios --format sarif            # SARIF for GitHub Security tab
trustwatch scan core-js --no-github             # registry signals only
trustwatch scan lodash | jq '.risk'             # pipe to jq
```

---

### `batch` — manifest files

```bash
trustwatch batch <manifest> [options]

Options:
  -d, --days         Activity window (default: 90)
  -t, --token        GitHub token
  --no-github        Skip GitHub API
  --threshold        CI exit code 1 if any score >= this (default: 75)
  -f, --format       terminal | json | sarif | gha | markdown
  -o, --output       Save output to file
  --sort             score | name | ecosystem (default: score)
```

**Supported manifest formats:**

| File | Format | Auto-detected? |
|---|---|---|
| `requirements.txt` | pip requirements | Yes |
| `requirements-dev.txt` | pip requirements | Yes |
| `package.json` | npm manifest | Yes |
| `watchlist.txt` | plain list | Yes |

**Plain list format** (one package per line):
```
lodash
requests pypi
aquasecurity/trivy github
core-js npm
# comments are ignored
```

**Examples:**
```bash
# Python project
trustwatch batch requirements.txt

# JS project
trustwatch batch package.json --threshold 55

# Save SARIF for GitHub Security tab
trustwatch batch requirements.txt --format sarif --output results.sarif

# Save GitHub Actions step summary
trustwatch batch package.json --format gha --output summary.md

# Save markdown report
trustwatch batch watchlist.txt --format markdown --output report.md

# CI gate — exit 1 if any package is CRITICAL
trustwatch batch requirements.txt --threshold 75
echo $?  # 0 = all clear, 1 = action needed
```

---

### `history` — scan history

```bash
trustwatch history <package> [options]

Options:
  -e, --ecosystem    npm | pypi | github (default: npm)
  -n, --limit        Number of past scans to show (default: 10)
  --json             Output as JSON
```

**Examples:**
```bash
trustwatch history lodash
trustwatch history requests --ecosystem pypi
trustwatch history lodash --limit 30
trustwatch history lodash --json | jq '.[0]'
```

**Sample output:**
```
History: lodash (npm)
────────────────────────────────────────────────────────────────────────
  Date                   Score  Level       Trend                 Top signal
  ──────────────────────────────────────────────────────────────────────
  2026-03-01 09:00          40  MEDIUM      (first scan)          Single person can publish...
  2026-03-15 09:00          78  CRITICAL    ↑ +38 sharply rising  New actor dominating...
  2026-03-22 09:00          34  LOW         ↓ -44 falling         No significant risk...
  ──────────────────────────────────────────────────────────────────────
  3 scans on record
```

The score spike on March 15 is visible even though March 22 looks clean. That's the killer feature — you see the incident window even after remediation.

---

### `watch` — continuous monitoring

```bash
trustwatch watch <manifest> [options]

Options:
  -i, --interval     Hours between scans (default: 24)
  --threshold        Alert threshold (default: 75)
  --alert-delta      Alert if score rises by this much (default: 15)
  -t, --token        GitHub token
  --no-github        Skip GitHub API
  -f, --format       terminal | gha | markdown
  --output-dir       Save each run's report to this directory
```

**Examples:**
```bash
# scan every 24 hours, alert on sharp rises
trustwatch watch watchlist.txt --interval 24

# aggressive monitoring — scan every 6 hours, alert on +10 rise
trustwatch watch package.json --interval 6 --alert-delta 10

# save reports to disk
trustwatch watch requirements.txt --output-dir ./reports

# run as a cron job (add to crontab)
# 0 9 * * * cd /path/to/project && trustwatch watch watchlist.txt --interval 1
```

---

## Output formats

### JSON (default for `scan`)
Full machine-readable report including all signal scores, delta, and blast radius.

### Terminal (default for `batch`, `watch`)
Colour-coded table sorted by risk, with delta column and CI gate summary.

### SARIF
Standard security tool output. Upload to GitHub Security tab via `upload-sarif` action.

```yaml
# .github/workflows/trustwatch.yml
- name: Run trustwatch
  run: trustwatch batch requirements.txt --format sarif --output results.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitHub Actions step summary (`gha`)
Renders as a formatted table in the GitHub Actions UI.

```yaml
- name: Run trustwatch
  run: |
    trustwatch batch package.json --format gha --output $GITHUB_STEP_SUMMARY
```

### Markdown
Standalone report suitable for documentation, Confluence, or email.

---

## Signals explained

trustwatch scores five signals and combines them into an overall risk score (0–100).

| Signal | Weight | What it measures |
|---|---|---|
| `publish_concentration` | 30% | How many distinct identities can publish a release alone |
| `maintainer_spof` | 20% | One person dominates commit + release history |
| `token_age_risk` | 10% | Proxy for stale long-lived credentials |
| `activity_delta` | 30% | New actors, velocity spikes, XZ-Utils infiltration pattern |
| `github_health` | 10% | Archived, abandoned, overwhelmed maintainer |

**Risk levels:**

| Level | Score | Action |
|---|---|---|
| LOW | 0–34 | No action needed |
| MEDIUM | 35–54 | Monitor; review on next dependency update |
| HIGH | 55–74 | Investigate; consider alternatives |
| CRITICAL | 75–100 | Immediate review; pin version; check for compromise |

**Pattern overrides** — force CRITICAL regardless of weighted score:

| Pattern | Condition |
|---|---|
| `xz_infiltration` | New actor dominating commits + already publishing releases |
| `solo_spof` | Single human maintainer with no backup (non-org-backed) |
| `burnout_abandonment` | Solo + stale tokens + no recent activity |

---

## GitHub rate limits

Without a token: 60 requests/hour (enough for ~12 packages).  
With a token: 5,000 requests/hour.

```bash
# PowerShell
$env:GITHUB_TOKEN = "ghp_yourtoken"

# bash
export GITHUB_TOKEN="ghp_yourtoken"
```

Get a free token at https://github.com/settings/tokens — no scopes needed.

If GitHub is blocked by your network:
```bash
trustwatch batch requirements.txt --no-github
```
Scores will use registry signals only (npm maintainer list, PyPI metadata). Less accurate but still useful — particularly for single-maintainer detection.

---

## CI integration

### GitHub Actions

```yaml
name: Supply chain trust check

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 9 * * 1'   # weekly on Monday

jobs:
  trustwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install trustwatch
        run: pip install typer rich && pip install -e .

      - name: Scan dependencies
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          trustwatch batch requirements.txt \
            --format gha \
            --output $GITHUB_STEP_SUMMARY \
            --threshold 75

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
trustwatch batch requirements.txt --threshold 75 --no-github
if [ $? -ne 0 ]; then
  echo "trustwatch: CRITICAL packages detected. Review before committing."
  exit 1
fi
```

---

## History database

Scan history is stored in `.trustwatch_history.db` (SQLite) in the directory where you run trustwatch. You can inspect it directly:

```bash
sqlite3 .trustwatch_history.db "SELECT package, ecosystem, score, level, scanned_at FROM scans ORDER BY scanned_at DESC LIMIT 20;"
```

Or view all packages with history:
```bash
trustwatch history --json  # not yet implemented — use sqlite3 directly
```

---

## Architecture

```
trustwatch/
  __init__.py      version
  constants.py     bot patterns, trusted orgs, thresholds, weights
  http.py          shared HTTP helper (stdlib urllib, no deps)
  scanner.py       npm, PyPI, GitHub, deps.dev API calls
  scorer.py        5 signals + pattern overrides → risk score
  history.py       SQLite store, delta calculation, trends
  parsers.py       requirements.txt, package.json, plain list
  output.py        terminal, JSON, SARIF, GHA, Markdown formatters
  cli.py           Typer CLI — scan, batch, history, watch
```

---

## What trustwatch doesn't do

- **Detect malicious code** — use Socket.sh or Snyk for that
- **Scan lockfiles** — too many transitive deps; focus on direct dependencies
- **Verify cryptographic signatures** — use Sigstore/SLSA for that
- **Replace an SBOM** — use Syft/Trivy for inventory; trustwatch scores governance

trustwatch complements existing tools. It answers the question they don't: *who controls this package, and is that safe?*
