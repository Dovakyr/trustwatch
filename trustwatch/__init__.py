"""
trustwatch — OSS publish trust scanner.

Public API:
    scan_package(package, ecosystem, cfg) → Report
    score(result) → Report
    ScanConfig(days, token, no_github)
"""

from .constants import VERSION
from .models import Report, ScanResult, ScanConfig, Delta
from .scanner import scan_package
from .scorer import score

__version__ = VERSION
__all__ = [
    "__version__",
    "scan_package",
    "score",
    "Report",
    "ScanResult",
    "ScanConfig",
    "Delta",
]
