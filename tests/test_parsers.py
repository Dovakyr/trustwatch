"""
tests/test_parsers.py — unit tests for manifest file parsers.
No network calls, no file system beyond temp files.
"""

from __future__ import annotations

import json
import sys
import pathlib
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from trustwatch.parsers import (
    parse_requirements_txt,
    parse_package_json,
    parse_plain_txt,
    detect_and_parse,
)
from trustwatch.exceptions import ParseError


class TestRequirementsTxt:
    def test_simple_pin(self) -> None:
        entries = parse_requirements_txt("requests==2.33.1\n")
        assert entries == [("requests", "pypi")]

    def test_range_specifier(self) -> None:
        entries = parse_requirements_txt("boto3>=1.34\n")
        assert ("boto3", "pypi") in entries

    def test_extras_stripped(self) -> None:
        entries = parse_requirements_txt("flask[security]>=3.0\n")
        assert ("flask", "pypi") in entries

    def test_compatible_release(self) -> None:
        entries = parse_requirements_txt("pytest~=8.0\n")
        assert ("pytest", "pypi") in entries

    def test_exclusion_specifier(self) -> None:
        entries = parse_requirements_txt("black!=24.0\n")
        assert ("black", "pypi") in entries

    def test_include_directive_skipped(self) -> None:
        entries = parse_requirements_txt("-r other.txt\n")
        assert entries == []

    def test_comments_skipped(self) -> None:
        entries = parse_requirements_txt("# this is a comment\n")
        assert entries == []

    def test_blank_lines_skipped(self) -> None:
        entries = parse_requirements_txt("\n\n\n")
        assert entries == []

    def test_vcs_skipped(self) -> None:
        entries = parse_requirements_txt("git+https://github.com/x/y\n")
        assert entries == []

    def test_all_pypi_ecosystem(self) -> None:
        text = "requests==2.33\nboto3>=1\nflask[sec]>=3\n"
        entries = parse_requirements_txt(text)
        assert all(eco == "pypi" for _, eco in entries)
        assert len(entries) == 3

    def test_complex_file(self) -> None:
        text = (
            "# Production dependencies\n"
            "requests==2.33.1\n"
            "boto3>=1.34\n"
            "flask[security]>=3.0\n"
            "\n"
            "# Dev dependencies\n"
            "pytest~=8.0\n"
            "black!=24.0\n"
            "-r dev-requirements.txt\n"
        )
        entries = parse_requirements_txt(text)
        assert len(entries) == 5
        pkgs = [p for p, _ in entries]
        assert "requests" in pkgs
        assert "boto3" in pkgs
        assert "flask" in pkgs
        assert "pytest" in pkgs
        assert "black" in pkgs


class TestPackageJson:
    def test_dependencies(self) -> None:
        data = json.dumps({"dependencies": {"lodash": "^4.17.21"}})
        entries = parse_package_json(data)
        assert ("lodash", "npm") in entries

    def test_dev_dependencies(self) -> None:
        data = json.dumps({"devDependencies": {"jest": "^29.0.0"}})
        entries = parse_package_json(data)
        assert ("jest", "npm") in entries

    def test_peer_dependencies(self) -> None:
        data = json.dumps({"peerDependencies": {"react": ">=18"}})
        entries = parse_package_json(data)
        assert ("react", "npm") in entries

    def test_local_file_skipped(self) -> None:
        data = json.dumps({"dependencies": {"my-local": "file:../local"}})
        entries = parse_package_json(data)
        assert entries == []

    def test_workspace_skipped(self) -> None:
        data = json.dumps({"dependencies": {"my-ws": "workspace:*"}})
        entries = parse_package_json(data)
        assert entries == []

    def test_link_skipped(self) -> None:
        data = json.dumps({"dependencies": {"my-link": "link:../other"}})
        entries = parse_package_json(data)
        assert entries == []

    def test_all_npm_ecosystem(self) -> None:
        data = json.dumps({
            "dependencies": {"lodash": "^4", "axios": "^1"},
            "devDependencies": {"jest": "^29"},
        })
        entries = parse_package_json(data)
        assert all(eco == "npm" for _, eco in entries)
        assert len(entries) == 3

    def test_invalid_json_raises(self) -> None:
        try:
            parse_package_json("not valid json {")
            assert False, "Should have raised ParseError"
        except ParseError:
            pass

    def test_non_object_raises(self) -> None:
        try:
            parse_package_json("[1, 2, 3]")
            assert False, "Should have raised ParseError"
        except ParseError:
            pass

    def test_missing_sections_ok(self) -> None:
        data = json.dumps({"name": "my-app", "version": "1.0"})
        entries = parse_package_json(data)
        assert entries == []


class TestPlainTxt:
    def test_package_only(self) -> None:
        entries = parse_plain_txt("lodash\n")
        assert ("lodash", "auto") in entries

    def test_package_with_ecosystem(self) -> None:
        entries = parse_plain_txt("requests pypi\n")
        assert ("requests", "pypi") in entries

    def test_github_slug(self) -> None:
        entries = parse_plain_txt("aquasecurity/trivy github\n")
        assert ("aquasecurity/trivy", "github") in entries

    def test_comments_skipped(self) -> None:
        entries = parse_plain_txt("# comment\n")
        assert entries == []

    def test_blank_lines_skipped(self) -> None:
        entries = parse_plain_txt("\n\n")
        assert entries == []

    def test_mixed_file(self) -> None:
        text = (
            "# watchlist\n"
            "lodash\n"
            "requests pypi\n"
            "aquasecurity/trivy github\n"
            "core-js npm\n"
        )
        entries = parse_plain_txt(text)
        assert len(entries) == 4
        assert ("requests", "pypi") in entries
        assert ("aquasecurity/trivy", "github") in entries


class TestDetectAndParse:
    def test_detects_requirements_txt(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="_requirements.txt",
            delete=False, encoding="utf-8"
        ) as f:
            f.write("requests==2.33\nboto3>=1\n")
            path = f.name

        # rename to proper filename for detection
        dest = pathlib.Path(path).parent / "requirements.txt"
        pathlib.Path(path).rename(dest)

        try:
            entries = detect_and_parse(str(dest))
            assert all(eco == "pypi" for _, eco in entries)
        finally:
            dest.unlink(missing_ok=True)

    def test_detects_package_json(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="_pkg.json",
            delete=False, encoding="utf-8"
        ) as f:
            f.write(json.dumps({"dependencies": {"lodash": "^4"}}))
            path = f.name

        dest = pathlib.Path(path).parent / "package.json"
        pathlib.Path(path).rename(dest)

        try:
            entries = detect_and_parse(str(dest))
            assert all(eco == "npm" for _, eco in entries)
        finally:
            dest.unlink(missing_ok=True)

    def test_file_not_found_raises(self) -> None:
        try:
            detect_and_parse("/nonexistent/path/requirements.txt")
            assert False, "Should have raised FileNotFoundError"
        except FileNotFoundError:
            pass

    def test_unsupported_extension_raises(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("lodash: ^4\n")
            path = f.name

        try:
            detect_and_parse(path)
            assert False, "Should have raised ParseError"
        except ParseError:
            pass
        finally:
            pathlib.Path(path).unlink(missing_ok=True)


# ── run without pytest ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    GREEN = "\033[92m"; RED = "\033[91m"; RESET = "\033[0m"; BOLD = "\033[1m"

    classes = [
        TestRequirementsTxt, TestPackageJson,
        TestPlainTxt, TestDetectAndParse,
    ]

    total = passed = 0
    for cls in classes:
        print(f"\n{BOLD}{cls.__name__}{RESET}")
        inst = cls()
        methods = [m for m in dir(inst) if m.startswith("test_")]
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
    print(f"Parser tests: {passed}/{total} passed")
    if passed == total:
        print(f"{GREEN}All passing.{RESET}")
    else:
        sys.exit(1)


class TestGitHubSlugExtraction:
    """
    Tests for _extract_npm_github_slug and _extract_pypi_github_slug.
    These cover the real-world URL shape variations we've observed in the wild.
    """

    def test_npm_repo_object_with_url(self) -> None:
        from trustwatch.scanner import _extract_npm_github_slug
        reg = {"repository": {"type": "git", "url": "https://github.com/chalk/chalk.git"}}
        assert _extract_npm_github_slug(reg) == "chalk/chalk"

    def test_npm_repo_plain_string(self) -> None:
        from trustwatch.scanner import _extract_npm_github_slug
        reg = {"repository": "https://github.com/npm/node-semver"}
        assert _extract_npm_github_slug(reg) == "npm/node-semver"

    def test_npm_repo_git_plus_https(self) -> None:
        from trustwatch.scanner import _extract_npm_github_slug
        reg = {"repository": {"url": "git+https://github.com/lodash/lodash.git"}}
        assert _extract_npm_github_slug(reg) == "lodash/lodash"

    def test_npm_homepage_readme_fragment(self) -> None:
        from trustwatch.scanner import _extract_npm_github_slug
        reg = {"homepage": "https://github.com/sindresorhus/got#readme"}
        assert _extract_npm_github_slug(reg) == "sindresorhus/got"

    def test_npm_bugs_url_fallback(self) -> None:
        from trustwatch.scanner import _extract_npm_github_slug
        reg = {"bugs": {"url": "https://github.com/uuidjs/uuid/issues"}}
        assert _extract_npm_github_slug(reg) == "uuidjs/uuid"

    def test_npm_bugs_plain_string(self) -> None:
        from trustwatch.scanner import _extract_npm_github_slug
        reg = {"bugs": "https://github.com/tj/commander.js/issues"}
        assert _extract_npm_github_slug(reg) == "tj/commander.js"

    def test_npm_no_links_returns_empty(self) -> None:
        from trustwatch.scanner import _extract_npm_github_slug
        assert _extract_npm_github_slug({}) == ""

    def test_npm_gitlab_not_extracted(self) -> None:
        from trustwatch.scanner import _extract_npm_github_slug
        reg = {"repository": {"url": "https://gitlab.com/org/repo"}}
        assert _extract_npm_github_slug(reg) == ""

    def test_pypi_source_key(self) -> None:
        from trustwatch.scanner import _extract_pypi_github_slug
        info = {"project_urls": {"Source": "https://github.com/psf/requests"}}
        assert _extract_pypi_github_slug(info) == "psf/requests"

    def test_pypi_source_code_key(self) -> None:
        from trustwatch.scanner import _extract_pypi_github_slug
        info = {"project_urls": {"Source Code": "https://github.com/org/pkg"}}
        assert _extract_pypi_github_slug(info) == "org/pkg"

    def test_pypi_repository_key(self) -> None:
        from trustwatch.scanner import _extract_pypi_github_slug
        info = {"project_urls": {"Repository": "https://github.com/org/pkg"}}
        assert _extract_pypi_github_slug(info) == "org/pkg"

    def test_pypi_github_key(self) -> None:
        from trustwatch.scanner import _extract_pypi_github_slug
        info = {"project_urls": {"GitHub": "https://github.com/org/pkg"}}
        assert _extract_pypi_github_slug(info) == "org/pkg"

    def test_pypi_bug_tracker_strips_issues(self) -> None:
        from trustwatch.scanner import _extract_pypi_github_slug
        info = {"project_urls": {"Bug Tracker": "https://github.com/org/pkg/issues"}}
        assert _extract_pypi_github_slug(info) == "org/pkg"

    def test_pypi_home_page_fallback(self) -> None:
        from trustwatch.scanner import _extract_pypi_github_slug
        info = {"home_page": "https://github.com/pypa/pip", "project_urls": {}}
        assert _extract_pypi_github_slug(info) == "pypa/pip"

    def test_pypi_no_links_returns_empty(self) -> None:
        from trustwatch.scanner import _extract_pypi_github_slug
        assert _extract_pypi_github_slug({}) == ""
    def test_npm_repo_only_in_version_metadata(self) -> None:
        """crypto-js pattern: repository not hoisted to top level."""
        from trustwatch.scanner import _extract_npm_github_slug
        reg = {
            "name": "crypto-js",
            "dist-tags": {"latest": "4.2.0"},
            "versions": {
                "4.2.0": {
                    "repository": {
                        "type": "git",
                        "url": "https://github.com/brix/crypto-js",
                    }
                }
            },
        }
        assert _extract_npm_github_slug(reg) == "brix/crypto-js"

    def test_npm_homepage_only_in_version_metadata(self) -> None:
        """Package with homepage in version but not top level."""
        from trustwatch.scanner import _extract_npm_github_slug
        reg = {
            "dist-tags": {"latest": "2.0"},
            "versions": {"2.0": {"homepage": "https://github.com/org/pkg"}},
        }
        assert _extract_npm_github_slug(reg) == "org/pkg"




if __name__ == "__main__":
    # re-run if called directly
    import subprocess, sys
    sys.exit(subprocess.call([sys.executable, __file__]))
