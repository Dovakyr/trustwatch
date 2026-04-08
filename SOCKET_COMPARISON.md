# trustwatch vs Socket.dev — Technical Comparison

## One-line difference

**Socket** detects malicious code after it exists.  
**trustwatch** detects the governance conditions that make an attack possible before any code changes.

---

## What each tool measures

### Socket.dev
Socket analyses the **contents and behaviour of package code**:
- Installs scripts that make network calls
- Obfuscated or minified source
- Newly added dependencies between versions
- Known malicious patterns (typosquatting, backdoor signatures)
- CVE matches
- Licence changes

Socket's signal source: the published package tarball + diff between versions.

### trustwatch
trustwatch analyses **who controls the package and whether that control is safe**:
- How many distinct humans can publish a release unilaterally
- Whether one person dominates commit and release history (SPOF)
- Whether publish credentials are likely stale
- Whether a new, previously unknown actor has appeared and started publishing
- Whether the project shows burnout/abandonment patterns

trustwatch's signal source: npm/PyPI registry metadata + GitHub API (commit graph, release publishers, contributor history).

---

## Why this matters — the XZ Utils case

In 2024, a state-sponsored attacker spent two years infiltrating the XZ Utils project:
- Created a legitimate-looking GitHub account ("Jia Tan")
- Made genuine contributions over 24 months
- Built trust with the maintainer (Lasse Collin)
- Gained commit and release rights
- Inserted a backdoor in a release that looked like normal maintenance

**What Socket would have seen at the moment of the attack:**
The backdoor was embedded in a binary test file and activated via a build script. A sophisticated code scanner might flag the binary or the build script change. But Socket's core signal — "does this package do something suspicious at install time" — would only fire after the malicious release was published.

**What trustwatch would have seen 6–12 months earlier:**
```
activity_delta signal:
  NEW ACTOR: jia-tan is dominating recent commits (41/50 in last 90d)
  jia-tan is NOT in the historical top contributor list
  jia-tan has started publishing releases
  → xz_infiltration pattern triggered → CRITICAL
```

This is a fundamentally different detection layer. trustwatch doesn't need to see the malicious code — it detects the preconditions.

---

## Technical signal comparison

| Signal | Socket | trustwatch |
|---|---|---|
| Malicious install script | ✅ Primary signal | ❌ Not measured |
| Obfuscated code | ✅ Detected | ❌ Not measured |
| New dependency added | ✅ Flagged | ❌ Not measured |
| CVE match | ✅ | ❌ Not measured |
| Publish concentration | ❌ | ✅ Primary signal |
| Maintainer SPOF | Partial (new maintainer flag) | ✅ Full commit graph analysis |
| Stale credentials (token age) | ❌ | ✅ Proxy via last-modified |
| New actor infiltration | Partial (new maintainer) | ✅ XZ-pattern detection |
| Burnout / abandonment | Partial (activity) | ✅ Full pattern |
| Blast radius | ❌ | ✅ Via deps.dev |
| Historical delta (score over time) | ❌ | ✅ SQLite history |
| Webhook alerting on change | ❌ | ✅ Slack/Discord/generic |

---

## Where Socket catches things trustwatch misses

If an attacker:
- Compromises an existing trusted account and makes no governance changes
- Inserts malicious code that bypasses behavioural heuristics
- Uses a supply chain attack via a build tool rather than a direct publish

Socket catches it at install time. trustwatch doesn't do code analysis.

**These are complementary layers, not competing tools.**

---

## Where trustwatch catches things Socket misses

### 1. Stale credential exposure (pre-attack)
lodash: one maintainer, token from 2019, 50M weekly downloads.  
No malicious code. No CVE. Socket sees nothing.  
trustwatch: CRITICAL. The attack surface exists today.

### 2. Active infiltration in progress
A new actor appears in commit history. Not yet a maintainer. Not yet publishing.
No code changes yet. Socket sees nothing.
trustwatch: `activity_delta.flags` → "New actor dominating recent commits: X"

### 3. Ownership transfer without announcement
A company acquires a startup. The startup's npm packages transfer to a new employee
with no public contribution history. No malicious code. No CVE.
Socket sees nothing. trustwatch detects the new publisher and fires.

### 4. Abandoned high-value package
crypto-js: explicitly discontinued, solo maintainer, stale. 8M weekly downloads.
Socket sees nothing wrong with the code. trustwatch: CRITICAL — burnout + solo + stale.

---

## Technical implementation differences

### How Socket gets its data
Socket fetches the package tarball and runs static analysis on the source code.
For npm: downloads `.tgz`, extracts, analyses JS/TS.
This requires downloading the package contents on every scan.

### How trustwatch gets its data
trustwatch never downloads package code.
It reads:
- **npm registry API**: maintainers, publish history, publisher per version
- **PyPI JSON API + XMLRPC**: package metadata, maintainer roles
- **GitHub API**: commit authors (filtered for bots), release publishers,
  historical contributors, repository health
- **deps.dev API**: cross-registry linking, dependent count

No code download. No static analysis. Governance-only signals.

### Why this is architecturally different
Socket's threat model: *what is in this code?*  
trustwatch's threat model: *who controls the ability to ship code?*

These map to different phases of the attack lifecycle:

```
Phase 1: Attacker identifies target package
Phase 2: Attacker builds access (account compromise, social engineering)
Phase 3: Attacker gains publish rights                ← trustwatch detects here
Phase 4: Attacker ships malicious version
Phase 5: Malicious code executes on install           ← Socket detects here
Phase 6: Incident discovered and reported
```

trustwatch operates at Phase 3. Socket operates at Phase 5.
Phase 3 detection is earlier and gives teams time to act before code ships.
Phase 5 detection requires the attack to have already partially succeeded.

---

## The honest overlap

Socket has a "Maintainer Risk" signal that checks:
- Is this a new maintainer who wasn't there before?
- Did the package recently change hands?

This overlaps with trustwatch's `activity_delta` signal.
The difference is depth: Socket flags the change, trustwatch tracks the pattern
over time (historical contributors vs recent commits) and detects infiltration
before the maintainer list officially changes.

Socket is heading toward this space. As of 2026 their coverage of governance
signals is limited compared to their code analysis coverage.

---

## Recommended deployment

Don't choose between them. Use both:

```
Socket    → catches malicious code at install time
trustwatch → catches governance risk before code ships
```

In a CI pipeline:
```yaml
- name: trustwatch (governance layer)
  run: trustwatch batch requirements.txt --threshold 75

- name: socket (code analysis layer)  
  run: npx @socketsecurity/cli scan
```

Two different threat phases. Both necessary.
