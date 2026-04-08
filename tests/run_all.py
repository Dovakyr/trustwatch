"""
tests/run_all.py — run all tests without pytest.

Usage:
    python tests/run_all.py
    python tests/run_all.py --tb       # show full tracebacks on failure
    python tests/run_all.py --verbose  # show all passes too

All test files can also be run individually:
    python tests/test_scorer.py
    python tests/test_parsers.py
    python tests/test_history.py
"""

from __future__ import annotations

import importlib
import sys
import pathlib
import traceback

# Allow running from repo root
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

SHOW_TB  = "--tb" in sys.argv
VERBOSE  = "--verbose" in sys.argv

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
RESET = "\033[0m";  BOLD = "\033[1m";  DIM = "\033[90m"

TEST_MODULES = [
    "tests.test_scorer",
    "tests.test_parsers",
    "tests.test_history",
    "tests.test_output",
]


def collect_classes(module) -> list:
    return [
        getattr(module, name)
        for name in dir(module)
        if name.startswith("Test") and isinstance(getattr(module, name), type)
    ]


def run_class(cls) -> tuple[int, int]:
    """Run all test_ methods on a class. Returns (passed, total)."""
    inst    = cls()
    methods = sorted(m for m in dir(inst) if m.startswith("test_"))
    passed  = 0
    total   = len(methods)

    for method_name in methods:
        try:
            if hasattr(inst, "setup_method"):
                inst.setup_method()
            getattr(inst, method_name)()
            if hasattr(inst, "teardown_method"):
                inst.teardown_method()
            if VERBOSE:
                print(f"    {GREEN}PASS{RESET}  {method_name}")
            passed += 1
        except Exception as exc:
            try:
                if hasattr(inst, "teardown_method"):
                    inst.teardown_method()
            except Exception:
                pass
            print(f"    {RED}FAIL{RESET}  {method_name}")
            print(f"         {DIM}{exc}{RESET}")
            if SHOW_TB:
                traceback.print_exc()

    return passed, total


def main() -> None:
    overall_passed = 0
    overall_total  = 0

    for module_name in TEST_MODULES:
        print(f"\n{BOLD}{module_name}{RESET}")
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            print(f"  {RED}IMPORT ERROR:{RESET} {exc}")
            if SHOW_TB:
                traceback.print_exc()
            continue

        classes = collect_classes(module)
        mod_passed = mod_total = 0

        for cls in classes:
            if VERBOSE:
                print(f"\n  {cls.__name__}")
            p, t = run_class(cls)
            mod_passed += p
            mod_total  += t
            if not VERBOSE:
                status = f"{GREEN}✓{RESET}" if p == t else f"{RED}✗{RESET}"
                print(f"  {status}  {cls.__name__} — {p}/{t}")

        overall_passed += mod_passed
        overall_total  += mod_total

    # Final summary
    print(f"\n{'═' * 55}")
    if overall_passed == overall_total:
        print(
            f"{GREEN}{BOLD}All {overall_total} tests passed.{RESET}"
        )
    else:
        failed = overall_total - overall_passed
        print(
            f"{RED}{BOLD}{failed} of {overall_total} tests failed.{RESET}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
