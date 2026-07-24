"""
Package data models for the Safety CLI.

This module re-exports the main model classes used throughout Safety:
  - Vulnerability / CVE / Severity / Fix  — vulnerability report data
  - SafetyRequirement / Package           — parsed dependency data
  - RequirementFile                       — parsed requirements files
  - SafetyCLI                             — CLI context object
  - ToolResult                            — result from tool interception
"""
from .obj import SafetyCLI
from .requirements import is_pinned_requirement
from .vulnerabilities import (
    Vulnerability,
    CVE,
    Severity,
    Fix,
    SafetyRequirement,
    Package,
    SafetyEncoder,
    RequirementFile,
)
from .tools import ToolResult

__all__ = [
    "Package",
    "SafetyCLI",
    "Vulnerability",
    "CVE",
    "Severity",
    "Fix",
    "is_pinned_requirement",
    "SafetyRequirement",
    "SafetyEncoder",
    "RequirementFile",
    "ToolResult",
]
