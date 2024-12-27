# static_analysis/__init__.py

from .yara_analysis import load_yara_rules, scan_artifact_with_yara

__all__ = ["load_yara_rules", "scan_artifact_with_yara"]
