# Changelog

## [0.4.0] — 2026-04-02

### Changed — professional rewrite
- **`models.py`** — typed dataclasses replace all raw dicts throughout the codebase
  (`ScanResult`, `Report`, `Signals`, `Delta`, `ScanConfig`, `BlastRadius`, etc.)
- **`exceptions.py`** — typed exception hierarchy replaces generic `RuntimeError`
  (`ScanError`, `NetworkError`, `RateLimitError`, `NotFoundError`, `ValidationError`, `ParseError`)
- **`validation.py`** — input validation layer; all inputs checked before any API call
- **`constants.py`** — all magic numbers named with intent
  (e.g. `XZ_PATTERN_ACTIVITY_MIN = 85`, `SPOF_SOLE_CONTRIBUTOR = 95`)
- **`scorer.py`** — fully typed signal functions returning dataclasses, not dicts
- **`scanner.py`** — explicit error types, no bare excepts, late imports removed
- **`history.py`** — typed `HistoryRecord` and `Delta` dataclasses
- **`cli.py`** — `ScanConfig` replaces `global _no_github`; logging to stderr;
  all inputs validated before work starts; `--verbose` flag for debug output
- **`output.py`** — clean typed formatters, no magic strings
- **`__init__.py`** — clean `__all__` defining public API

### Fixed
- `github_error` field properly typed as `Optional[str]`
- `ScanConfig.__post_init__` validates `days` range at construction
- History `compute_delta` never raises — returns safe Delta on DB error
- Webhook delivery logged at WARNING, not silently swallowed

---

## [0.3.0] — 2026-04-02
- PyPI XMLRPC roles API for accurate maintainer counts
- deps.dev API endpoint fixes (v3 correct paths)
- Webhook alerts for watch command (Slack/Discord/generic)

## [0.2.1] — 2026-04-02
- Blast radius in terminal output (coloured, human-readable counts)

## [0.2.0] — 2026-04-02
- Multi-file architecture, watch command, SARIF/GHA/MD output, deps.dev

## [0.1.0] — 2026-04-01
- Initial release — single file trustwatch.py
