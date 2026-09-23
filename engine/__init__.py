"""Remediation suggestion engine."""

from .prerequisites import (
    CvePrerequisites,
    Prerequisite,
    PrerequisiteType,
    load_prerequisites,
    parse_prerequisites,
)
from .suggester import (
    PlatformContext,
    RemediationOption,
    RemediationPath,
    RemediationPlan,
    suggest,
)

__all__ = [
    "CvePrerequisites",
    "PlatformContext",
    "Prerequisite",
    "PrerequisiteType",
    "RemediationOption",
    "RemediationPath",
    "RemediationPlan",
    "load_prerequisites",
    "parse_prerequisites",
    "suggest",
]
