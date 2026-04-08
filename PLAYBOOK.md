# trustwatch — Incident Response Playbook

This playbook covers how to use trustwatch when something looks wrong, and how to investigate a flagged package.

---

## When to use this playbook

- A package in your stack just scored CRITICAL
- A score jumped sharply between scans (sharply_rising trend)
- A supply chain incident was reported in the news for a package you use
- You're onboarding a new dependency and want to vet it

---

## Part 1 — Triage a CRITICAL score

### Step 1: Read the summary

```bash
trustwatch scan <package> --ecosystem <eco> | jq '.summary'
```

The summary is plain English. Each item maps to a specific signal:

| Summary text | Signal | Meaning |
|---|---|---|
| "Single person can publish alone" | publish_concentration | 1 maintainer account has full release rights |
| "X is the sole human contributor" | maintainer_spof | No backup; 1 person leaving = project orphaned |
| "New actor(s) dominating recent commits" | activity_delta | Someone new took over — verify this is legitimate |
| "CRITICAL: X is new but already publishing" | activity_delta | XZ-Utils pattern — immediate investigation needed |
| "Last modified Nd ago — tokens likely stale" | token_age_risk | Credentials may not have been rotated in years |
| "No recent publishes — possible abandonment" | activity_delta | Project may be unmaintained |

---

### Step 2: Check which pattern fired

```bash
trustwatch scan <package> | jq '.risk.patterns_triggered'
```

| Pattern | Urgency | What to do |
|---|---|---|
| `xz_infiltration` | **Immediate** | Treat as potential active compromise. Pin current known-good version. Check recent commits manually. |
| `solo_spof` | High | No active threat, but high fragility. Check if maintainer is still active. Consider alternatives. |
| `burnout_abandonment` | Medium | Project may be unmaintained. Find an actively maintained fork. |

---

### Step 3: Check the delta

```bash
trustwatch history <package> --ecosystem <eco>
```

Look at the trend:
- **First scan / stable** — no change; evaluate absolute score
- **sharply_rising** — something changed recently; investigate what
- **sharply_falling after high score** — possible incident cleanup; the spike is the signal

If history shows a spike: look at *when* the score was highest. That timestamp tells you when the risk window opened.

---

### Step 4: Investigate manually

For `xz_infiltration` or any sharp rise:

**Check recent commits on GitHub:**
```
https://github.com/<org>/<repo>/commits/<default_branch>
```
Look for:
- Commits from accounts not in the historical contributor list
- Commits at unusual hours (compare to maintainer's timezone)
- Commits that modify build scripts, release workflows, or `.github/` files
- Unsigned commits from accounts that previously signed

**Check recent releases:**
```
https://github.com/<org>/<repo>/releases
```
Look for:
- Releases published by a new account
- Releases with unusual timing (late night, weekends, just before holidays)
- Version numbers that don't follow the project's usual scheme

**Check npm/PyPI publish history:**
```bash
# npm — who published recent versions?
curl https://registry.npmjs.org/<package> | jq '.time'

# PyPI — check release dates
curl https://pypi.org/pypi/<package>/json | jq '.releases | to_entries | .[-5:]'
```

---

### Step 5: Decide and act

| Finding | Action |
|---|---|
| New actor is legitimate (successor, org transfer) | Document. Reduce alert threshold for this package. |
| New actor is suspicious / unrecognised | Pin to last known-good version immediately. Report to package maintainer and registry. |
| Package abandoned | Find actively maintained fork. Add to removal backlog. |
| Confirmed compromise | See Part 2 — Incident Response. |

---

## Part 2 — Confirmed or suspected compromise

### Immediate actions (within 1 hour)

**1. Pin the version.**
Do not upgrade to any version published after the suspicious timestamp.

```bash
# requirements.txt — pin exactly
requests==2.32.3   # known good — do not update

# package.json — pin exactly
"axios": "1.14.0"  # do not use ^, ~, or ranges
```

**2. Check if you installed the bad version.**

```bash
# Python — what's installed?
pip show <package>

# npm — what's in lockfile?
grep -A 2 '"<package>"' package-lock.json
```

**3. Check if the malicious version ran in your CI.**

Look for any pipeline run that installed the package between the suspected compromise timestamp and the clean version timestamp.

Signs of execution:
- Unexpected outbound network connections in CI logs
- New SSH keys or credentials appearing in CI
- Unexpected process spawns during `npm install` or `pip install`

**4. Assume all CI secrets are compromised.**

If the malicious version ran in CI, treat all secrets accessible during that run as compromised:
- GitHub tokens and PATs
- Cloud provider credentials (AWS, GCP, Azure)
- npm/PyPI tokens
- Docker Hub credentials
- Database passwords in environment variables

Rotate immediately.

**5. Check developer machines.**

If any developer ran `npm install` or `pip install` during the window, their machine may have a RAT or infostealer installed. Isolate and rebuild.

---

### Within 24 hours

**Report to the registry:**
- npm: https://www.npmjs.com/support (report malicious package)
- PyPI: https://pypi.org/security/ (security@pypi.org)
- GitHub: https://github.com/contact/security

**Report to the project maintainer:**
Open a security advisory if the repo has one, or email directly. Be specific: which version, which commit, what was found.

**Pin all dependencies in CI**, not just the affected one. This is a good practice regardless.

```yaml
# GitHub Actions — pin actions by SHA, not tag
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

**Audit similar packages** you depend on. If an attacker targeted one package in your stack, they may target adjacent ones.

```bash
trustwatch batch requirements.txt --threshold 55
```

---

### Within 1 week

**Post-incident review:**
- Which signal would have caught this earliest?
- Is the delta feature configured? Would a score spike have been visible?
- Do you have watch mode running? If not, set it up.

**Improve your posture:**
- Add `trustwatch batch` to your CI pipeline
- Set up `trustwatch watch` with alerting
- Lower your threshold from 75 (CRITICAL only) to 55 (HIGH+) for sensitive projects

---

## Part 3 — Evaluating a new dependency

Before adding a new package to your project:

```bash
# 1. Check trust score
trustwatch scan <package> --ecosystem <eco>

# 2. Check blast radius — how widely used is this?
trustwatch scan <package> | jq '.blast_radius'

# 3. If MEDIUM or above, check signals
trustwatch scan <package> | jq '.risk.signals'
```

**Decision framework:**

| Score | Blast radius | Action |
|---|---|---|
| LOW | Any | Proceed |
| MEDIUM | < 10k dependents | Proceed with monitoring |
| MEDIUM | > 10k dependents | Review manually before adding |
| HIGH | Any | Evaluate alternatives; strong justification needed |
| CRITICAL | Any | Do not add; find alternative |

**Questions to ask for HIGH/CRITICAL:**
- Is there an org-backed alternative?
- Can we vendor this and own the code directly?
- Is this a transitive dependency we can avoid by choosing a different top-level package?
- If we must use it, can we pin to a specific version and audit before each upgrade?

---

## Part 4 — Setting up continuous monitoring

### Minimal setup (30 minutes)

**1. Create a watchlist:**
```bash
# watchlist.txt
lodash
requests pypi
core-js npm
# add your highest-risk dependencies
```

**2. Run watch mode:**
```bash
export GITHUB_TOKEN=ghp_yourtoken
trustwatch watch watchlist.txt --interval 24 --alert-delta 15
```

**3. Save to cron (Linux/Mac):**
```bash
# crontab -e
0 9 * * * cd /path/to/project && \
  trustwatch batch watchlist.txt --format markdown --output /path/to/reports/$(date +\%Y\%m\%d).md
```

**4. GitHub Actions (weekly):**
```yaml
name: trustwatch weekly scan
on:
  schedule:
    - cron: '0 9 * * 1'
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install typer rich && pip install -e .
      - run: |
          trustwatch batch requirements.txt \
            --format gha >> $GITHUB_STEP_SUMMARY
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Signal reference

### publish_concentration

**What:** How many distinct identities can publish a release alone.

**Data sources:** npm maintainer list, PyPI maintainer field, GitHub release publishers.

**Limitation:** PyPI API doesn't expose publisher per release. Score uses maintainer field as proxy.

**Trusted org reduction:** PSF, OpenJS Foundation, Apache, AWS, Google, and other known-governance orgs get a 25-point reduction because they have MFA requirements and succession plans.

---

### maintainer_spof

**What:** Does one person dominate commit and release history?

**Data sources:** GitHub commit authors (filtered to remove bots), npm/PyPI maintainer list as fallback when GitHub unavailable.

**Bot filtering:** Accounts matching bot patterns (dependabot, renovate-bot, github-actions, aws-sdk-python-automation, etc.) are excluded before calculating share.

**Registry fallback:** When GitHub is unavailable, uses npm/PyPI maintainer count. Less precise but still surfaces single-maintainer packages.

**Solo override:** A package with exactly 1 human maintainer forces CRITICAL regardless of token age or activity — being actively maintained by one person is still a single point of failure.

---

### token_age_risk

**What:** Proxy for stale long-lived credentials.

**Data sources:** npm `time.modified`, GitHub `pushed_at`.

**Limitation:** This is a proxy, not a direct credential check. A recently-active package may still use old tokens; an old package may have rotated credentials. Use as a supporting signal, not a primary one.

---

### activity_delta

**What:** Changes in commit patterns that may signal a takeover or new threat actor.

**Signals detected:**
- New actor dominating recent commits (not in historical top contributors)
- New actor also publishing releases (XZ-Utils pattern)
- Unusual publish velocity (>10 releases in 90 days)
- Long silence after historically active project

**XZ-Utils pattern:** When an account that wasn't in the historical contributor list suddenly dominates commits AND has published releases, this combination triggers a CRITICAL override. This is the exact pattern used in the XZ Utils backdoor.

---

### github_health

**What:** Repository-level signals of abandonment or overwhelm.

**Signals:** Archived repo, no pushes in 180+ days, 500+ open issues.

**Limitation:** Healthy repos can still have compromised maintainers. Use as context, not a primary signal.
