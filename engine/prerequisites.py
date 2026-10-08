"""Reader for a CVE prerequisite file, as described by prereq_scheme.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from typing import Any

import yaml


class PrerequisiteType(Enum):
    """Prerequisite row types the engine knows about."""

    SOFTWARE_COMPONENT = "software_component"
    CONFIGURATION = "configuration"
    NETWORK_SERVICE = "network_service"
    HUMAN_INTERACTION = "human_interaction"
    PRIVILEGE = "privilege"
    VANTAGE = "vantage"
    OTHER = "other"

    @classmethod
    def _missing_(cls, value: object) -> "PrerequisiteType":
        return cls.OTHER


@dataclass(frozen=True, slots=True)
class VersionBound:
    """One end of a version range."""

    version: str
    inclusive: bool


@dataclass(frozen=True, slots=True)
class VersionRange:
    """Versions between two bounds. A missing bound is open."""

    min: VersionBound | None = None
    max: VersionBound | None = None


@dataclass(frozen=True, slots=True)
class VersionConstraint:
    """Versions a prerequisite names as affected.

    exact_versions are specific versions. ranges cover every version between
    their bounds. Both may be set; an empty constraint names no version.
    """

    exact_versions: tuple[str, ...] = ()
    ranges: tuple[VersionRange, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.exact_versions and not self.ranges


@dataclass(frozen=True, slots=True)
class Prerequisite:
    """One prerequisite row of a CVE."""

    id: str
    type: PrerequisiteType
    display_id: str
    raw_type: str = ""
    title: str | None = None
    description: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        """Name to show the customer."""
        return self.title or self.display_id.replace("-", " ")

    @property
    def affected_versions(self) -> VersionConstraint | None:
        """Every version the prerequisite file names as affected.

        Specific versions stay exact. A range stays a range, including an open
        bound. A null version means the file does not name one.
        """
        version = self.parameters.get("version")
        if not isinstance(version, dict):
            return None
        exact = tuple(str(value) for value in version.get("exact_versions") or () if value)
        ranges = []
        for entry in version.get("ranges") or ():
            if not isinstance(entry, dict):
                continue
            ranges.append(VersionRange(min=_bound(entry.get("min")), max=_bound(entry.get("max"))))
        constraint = VersionConstraint(exact_versions=exact, ranges=tuple(ranges))
        return None if constraint.is_empty else constraint

    @property
    def fixed_version(self) -> str | None:
        """Lowest version stated to be unaffected, when the file gives one."""
        version = self.parameters.get("version")
        if not isinstance(version, dict):
            return None
        fixed = None
        for entry in version.get("ranges") or ():
            upper = (entry or {}).get("max") or {}
            value = upper.get("version")
            if value and not upper.get("inclusive", False):
                fixed = str(value)
        return fixed

    @property
    def direction(self) -> str:
        """inbound or outbound, for a network service row."""
        return str(self.parameters.get("direction") or "inbound")

    @property
    def required_value(self) -> str | None:
        """Setting value that makes the system vulnerable."""
        value = self.parameters.get("value")
        return None if value is None else str(value)

    @property
    def vulnerable_by_default(self) -> bool:
        return bool(self.parameters.get("vulnerable_by_default"))


@dataclass(frozen=True, slots=True)
class CvePrerequisites:
    """Everything one prerequisite file states about a single CVE."""

    cve_id: str
    prerequisites: tuple[Prerequisite, ...]
    summary: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None

    def of_type(self, *types: PrerequisiteType) -> tuple[Prerequisite, ...]:
        return tuple(row for row in self.prerequisites if row.type in types)


def _bound(raw: Any) -> VersionBound | None:
    if not isinstance(raw, dict):
        return None
    version = raw.get("version")
    if not version:
        return None
    return VersionBound(version=str(version), inclusive=bool(raw.get("inclusive", False)))


def parse_prerequisites(document: dict[str, Any]) -> CvePrerequisites:
    """Build a CvePrerequisites from an already-loaded YAML document."""
    if not isinstance(document, dict):
        raise ValueError("prerequisite file must contain a mapping at the top level")

    cve_id = document.get("cve_id")
    if not cve_id:
        raise ValueError("prerequisite file is missing cve_id")

    rows = document.get("prerequisites")
    if not isinstance(rows, list):
        raise ValueError(f"{cve_id}: prerequisites must be a list")

    parsed = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{cve_id}: prerequisite #{index + 1} must be a mapping")
        raw_type = str(row.get("type") or "")
        parameters = row.get("parameters")
        parsed.append(
            Prerequisite(
                id=str(row.get("id") or f"{cve_id}-prerequisite-{index + 1}"),
                type=PrerequisiteType(raw_type),
                display_id=str(row.get("catalog_record_display_id") or ""),
                raw_type=raw_type,
                title=row.get("title"),
                description=row.get("description"),
                parameters=parameters if isinstance(parameters, dict) else {},
            )
        )

    score = document.get("cvss_score")
    return CvePrerequisites(
        cve_id=str(cve_id),
        prerequisites=tuple(parsed),
        summary=document.get("summary"),
        cvss_vector=document.get("cvss_vector"),
        cvss_score=float(score) if isinstance(score, (int, float)) else None,
    )


def load_prerequisites(path: str | Path) -> CvePrerequisites:
    """Read a prerequisite YAML file from disk."""
    with open(path, "r", encoding="utf-8") as handle:
        return parse_prerequisites(yaml.safe_load(handle))
