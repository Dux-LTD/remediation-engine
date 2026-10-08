"""Turns the prerequisites of one CVE into remediation suggestions.

A CVE is exploitable only when all of its prerequisites hold, so removing any
single one of them remediates it. The engine therefore returns alternative
paths: each path on its own closes the issue, and the customer picks one.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime

from defs.def_components import RemediationTag, Role, SOFTWARE_COMPONENTS, SoftwareComponent
from defs.def_remediation_plans import (
    ACTIONS_BY_ID,
    ActionCategory,
    CONFIGURATION_ACTIONS,
    EOL_SENTENCES,
    EOL_SINCE,
    EOL_UNTIL,
    NETWORK_ACTIONS,
    RemediationAction,
    render_detail,
)

from .eol import EolUnavailable, ProductReleases, Release, fetch_releases
from .prerequisites import CvePrerequisites, Prerequisite, PrerequisiteType, VersionRange

# eol_slug -> that product's release cycles; engine.eol.fetch_releases by default.
EolLookup = Callable[[str], ProductReleases]

def _catalog_key(text: str) -> str:
    """Normalize a display name or kebab id for catalog lookup."""
    return re.sub(r"[^a-z0-9]+", "-", text.casefold()).strip("-")


COMPONENTS_BY_ID: dict[str, SoftwareComponent] = dict(SOFTWARE_COMPONENTS)  # by display_id
for _component in SOFTWARE_COMPONENTS.values():
    COMPONENTS_BY_ID.setdefault(_component.display_name, _component)
    COMPONENTS_BY_ID.setdefault(_catalog_key(_component.display_name), _component)

# Roles that mean "the whole OS or firmware itself" (logic v2, rule 5).
WHOLE_OS_ROLES = frozenset({Role.OS, Role.FIRMWARE})


# Words dropped from a configuration name inside a description only.
_SETTING_STATE_WORDS = re.compile(r"\b(?:enabled|disabled)\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class RemediationOption:
    """One way to carry out a path. Options inside a path are alternatives."""

    action: RemediationAction
    detail: str
    condition: str | None = None


@dataclass(frozen=True, slots=True)
class RemediationPath:
    """A change to one prerequisite that, on its own, remediates the CVE."""

    target_display_id: str
    target_label: str
    layer: ActionCategory
    options: tuple[RemediationOption, ...]
    recommended: bool = False
    eol: "EolCoverage | None" = None


@dataclass(frozen=True, slots=True)
class PlatformContext:
    """Operating system a CVE is scoped to, when the fix is in a product on it."""

    display_id: str
    label: str
    is_firmware: bool


@dataclass(frozen=True, slots=True)
class EolCoverage:
    """End-of-life status of every version a prerequisite names."""

    slug: str
    lines: tuple[Release, ...]
    exact_versions: tuple[str, ...]
    ranges: tuple[VersionRange, ...]
    unmatched_exact: tuple[str, ...]
    latest_supported: Release | None
    fetched_at: str
    live: bool

    @property
    def eol_lines(self) -> tuple[Release, ...]:
        return tuple(line for line in self.lines if line.is_eol)

    @property
    def supported_lines(self) -> tuple[Release, ...]:
        return tuple(line for line in self.lines if not line.is_eol)

    @property
    def all_eol(self) -> bool:
        return bool(self.lines) and all(line.is_eol for line in self.lines)

    @property
    def all_supported(self) -> bool:
        return bool(self.lines) and all(not line.is_eol for line in self.lines)


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    """The suggestion for one CVE."""

    cve_id: str
    paths: tuple[RemediationPath, ...]
    platform_context: tuple[PlatformContext, ...] = ()
    notes: tuple[str, ...] = ()
    cvss_score: float | None = None
    cvss_vector: str | None = None


def suggest(
    cve: CvePrerequisites,
    eol_lookup: EolLookup | None = None,
) -> RemediationPlan:
    """Suggest remediation paths for one CVE.

    Every exact version is checked, and every release line a range overlaps is
    checked. Only components with a named version and an eol_slug get a live
    EOL check.
    """
    software_rows = cve.of_type(PrerequisiteType.SOFTWARE_COMPONENT)
    targets, platform_rows, ignored_rows = _split_software_rows(software_rows)
    platform_context = tuple(_platform_context(row) for row in platform_rows)
    lookup = eol_lookup or fetch_releases

    paths: list[RemediationPath] = []
    eol_notes: list[str] = []
    for row in targets:
        status = _eol_status(row, lookup, eol_notes)
        paths.append(_software_path(row, platform_context, status))
    for row in cve.of_type(PrerequisiteType.CONFIGURATION):
        paths.append(_configuration_path(row))
    for row in cve.of_type(PrerequisiteType.NETWORK_SERVICE):
        paths.append(_network_path(row))

    return RemediationPlan(
        cve_id=cve.cve_id,
        paths=tuple(paths),
        platform_context=platform_context,
        notes=_notes(cve, targets, platform_context, ignored_rows) + tuple(eol_notes),
        cvss_score=cve.cvss_score,
        cvss_vector=cve.cvss_vector,
    )


def _component_of(row: Prerequisite) -> SoftwareComponent | None:
    return COMPONENTS_BY_ID.get(row.display_id)


def _is_ignored(row: Prerequisite) -> bool:
    component = _component_of(row)
    return component is not None and component.remediation_tag is RemediationTag.IGNORE


def _is_whole_os(row: Prerequisite) -> bool:
    """True when the row is the whole OS or firmware itself (role os / firmware)."""
    component = _component_of(row)
    return component is not None and component.role in WHOLE_OS_ROLES


def _split_software_rows(
    rows: tuple[Prerequisite, ...],
) -> tuple[tuple[Prerequisite, ...], tuple[Prerequisite, ...], tuple[Prerequisite, ...]]:
    """Choose what to remediate, what is only platform context, and what is ignored.

    Returns (targets, platform_rows, ignored_rows):
    - Ignore-tagged rows are set aside first; no remediation is generated for them.
    - A whole OS or firmware (role os / firmware) next to any other remaining
      component is context only: the other components are what gets fixed.
    - When only whole-OS / firmware rows remain, every one of them is a target.
    """
    ignored_rows = tuple(row for row in rows if _is_ignored(row))
    remaining = tuple(row for row in rows if not _is_ignored(row))
    whole_os_rows = tuple(row for row in remaining if _is_whole_os(row))
    other_rows = tuple(row for row in remaining if not _is_whole_os(row))
    if other_rows:
        return other_rows, whole_os_rows, ignored_rows
    return whole_os_rows, (), ignored_rows


def _platform_context(row: Prerequisite) -> PlatformContext:
    component = _component_of(row)
    return PlatformContext(
        display_id=row.display_id,
        label=row.label,
        is_firmware=component is not None and component.role is Role.FIRMWARE,
    )


def _mark(name: str) -> str:
    """Mark an inserted name so the page can give it a background."""
    return f"`{name}`"


def _configuration_name(label: str) -> str:
    """Configuration name for a description, without enabled or disabled."""
    name = _SETTING_STATE_WORDS.sub("", label)
    name = re.sub(r"\s{2,}", " ", name).strip(" -")
    return name or label


def _platform_sentence(platform_context: tuple[PlatformContext, ...]) -> str:
    if not platform_context:
        return ""
    names = ", ".join(_mark(item.label) for item in platform_context)
    return f" This applies to the affected systems running {names}."


def _eol_status(row: Prerequisite, lookup: EolLookup, notes: list[str]) -> EolCoverage | None:
    """Live EOL check of every affected version, when the row names any."""
    versions = row.affected_versions
    component = _component_of(row)
    if versions is None or component is None or not component.eol_slug or component.discontinued:
        return None
    name = _mark(row.label)
    try:
        product = lookup(component.eol_slug)
    except EolUnavailable:
        notes.append(
            f"The end-of-life status of {name} could not be checked: "
            f"endoflife.date could not be reached and there is no earlier copy of its data."
        )
        return None
    if not product.live:
        notes.append(
            f"End-of-life data for {name} is from {product.fetched_at[:10]}, because "
            f"endoflife.date could not be reached for this suggestion."
        )

    lines: list[Release] = []
    unmatched = []
    for version in versions.exact_versions:
        release = product.release_for(version)
        if release is None:
            unmatched.append(version)
        elif all(release.name != line.name for line in lines):
            lines.append(release)
    unmatched_ranges = []
    for span in versions.ranges:
        matched = product.releases_overlapping(
            span.min.version if span.min else None,
            span.min.inclusive if span.min else True,
            span.max.version if span.max else None,
            span.max.inclusive if span.max else False,
        )
        if not matched:
            unmatched_ranges.append(span)
        for release in matched:
            if all(release.name != line.name for line in lines):
                lines.append(release)

    for version in unmatched:
        notes.append(
            f"Version {_mark(version)} of {name} matches no release line on endoflife.date, "
            f"so its end-of-life status is unknown."
        )
    for span in unmatched_ranges:
        notes.append(
            f"Affected versions {_range_phrase(span)} of {name} match no release line on "
            f"endoflife.date, so their end-of-life status is unknown."
        )
    if not lines:
        return None
    return EolCoverage(
        slug=product.slug,
        lines=tuple(lines),
        exact_versions=versions.exact_versions,
        ranges=versions.ranges,
        unmatched_exact=tuple(unmatched),
        latest_supported=product.latest_supported,
        fetched_at=product.fetched_at,
        live=product.live,
    )


def _software_path(
    row: Prerequisite,
    platform_context: tuple[PlatformContext, ...],
    eol: EolCoverage | None = None,
) -> RemediationPath:
    component = _component_of(row)
    name = _mark(row.label)
    platform = _platform_sentence(platform_context)

    if component is not None and component.discontinued:
        # End of life with no successor: removing it is the only fix.
        action_ids = ["remove-component"]
    elif eol is not None and eol.all_eol and eol.latest_supported is None:
        action_ids = ["remove-component"]
    elif eol is not None and eol.all_eol:
        action_ids = ["replace-component"]
    else:
        # Logic v2 routing: the remediation tag decides OS/firmware update vs
        # vendor patch; the role decides firmware vs OS update.
        if component is not None and component.remediation_tag is RemediationTag.OS:
            update_id = "firmware-update" if component.role is Role.FIRMWARE else "os-update"
        else:
            update_id = "software-update"
        if eol is not None and eol.all_supported:
            action_ids = [update_id]
        else:
            action_ids = [update_id, "replace-component"]

    eol_sentence = _eol_sentence(eol)
    options = []
    for action_id in action_ids:
        option = _option(ACTIONS_BY_ID[action_id], name=name, platform=platform, eol=eol_sentence)
        if eol is not None and (eol.all_eol or eol.all_supported):
            option = replace(option, condition=None)
        options.append(option)
    options = tuple(options)
    return RemediationPath(
        target_display_id=row.display_id,
        target_label=row.label,
        layer=options[0].action.category,
        options=options,
        recommended=True,
        eol=eol,
    )


def _eol_sentence(eol: EolCoverage | None) -> str:
    """End-of-life sentence for a software detail, from defs."""
    if eol is None or not eol.lines:
        return ""
    date = _month_year(eol.fetched_at)
    latest_release = eol.latest_supported
    latest = _mark(latest_release.display()) if latest_release else ""
    until = ""
    if latest_release is not None and latest_release.eol_from:
        until = EOL_UNTIL.format(date=latest_release.eol_from)
    values = {
        "subject": _version_subject(eol),
        "lines": _line_phrase(eol.lines),
        "eol_lines": _line_phrase(eol.eol_lines),
        "supported_lines": _line_phrase(eol.supported_lines),
        "latest": latest,
        "until": until,
        "date": date,
    }
    if eol.all_eol and eol.latest_supported is None:
        return EOL_SENTENCES["eol_no_successor"].format(**values)
    if eol.all_eol:
        return EOL_SENTENCES["eol"].format(**values)
    if eol.all_supported:
        return EOL_SENTENCES["supported"].format(**values)
    return EOL_SENTENCES["mixed"].format(**values)


def _version_subject(eol: EolCoverage) -> str:
    """Name every affected version the sentence is about."""
    chunks = []
    known = [version for version in eol.exact_versions if version not in eol.unmatched_exact]
    if len(known) == 1:
        chunks.append(f"version {_mark(known[0])}")
    elif known:
        chunks.append(f"versions {_join_marked(known)}")
    spans = [_range_phrase(span) for span in eol.ranges]
    if spans:
        chunks.append("versions " + " and ".join(spans))
    verb = "is" if len(known) == 1 and not spans else "are"
    named = " and ".join(chunks) if chunks else "versions"
    return f"Affected {named} {verb}"


def _range_phrase(span: VersionRange) -> str:
    """from 9.0.0 before 10.0, or the open form when a bound is missing."""
    lower = ""
    upper = ""
    if span.min:
        word = "from" if span.min.inclusive else "after"
        lower = f"{word} {_mark(span.min.version)}"
    if span.max:
        word = "through" if span.max.inclusive else "before"
        upper = f"{word} {_mark(span.max.version)}"
    if lower and upper:
        return f"{lower} {upper}"
    return lower or upper or "in an open range"


def _line_phrase(lines: tuple[Release, ...]) -> str:
    """9 on 2024-03-31, 10.1."""
    bits = []
    for line in lines:
        since = EOL_SINCE.format(date=line.eol_from) if line.is_eol and line.eol_from else ""
        bits.append(f"the {_mark(line.name)} line{since}")
    return _join(bits)


def _join_marked(values: list[str]) -> str:
    return _join([_mark(value) for value in values])


def _join(parts: list[str]) -> str:
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def _month_year(fetched_at: str) -> str:
    """Month and year of the end-of-life check behind this suggestion."""
    moment = datetime.fromisoformat(fetched_at)
    return moment.strftime("%B %Y")


def _configuration_path(row: Prerequisite) -> RemediationPath:
    name = _mark(_configuration_name(row.label))
    value = row.required_value
    state = f" The issue applies while it is set to {_mark(value)}." if value else ""
    if row.vulnerable_by_default:
        state += " This is the default setting, so it is likely in place."

    options = tuple(_option(action, name=name, state=state) for action in CONFIGURATION_ACTIONS)
    return RemediationPath(
        target_display_id=row.display_id,
        target_label=row.label,
        layer=ActionCategory.CONFIGURATION,
        options=options,
    )


def _network_path(row: Prerequisite) -> RemediationPath:
    service = row.label
    outbound = row.direction == "outbound"
    options = tuple(
        _option(action, outbound=outbound, service=_mark(service)) for action in NETWORK_ACTIONS
    )
    return RemediationPath(
        target_display_id=row.display_id,
        target_label=service,
        layer=ActionCategory.NETWORK,
        options=options,
    )


def _option(action: RemediationAction, outbound: bool = False, **values: str) -> RemediationOption:
    """One option: the action, its filled detail, and its condition, all from defs."""
    return RemediationOption(
        action=action,
        detail=render_detail(action, outbound=outbound, **values),
        condition=action.condition,
    )


def _ignored_note(ignored_rows: tuple[Prerequisite, ...], all_ignored: bool) -> str:
    """Explain Ignore-tagged components.

    Ignore-tagged catalog records name a kind of software (for example any
    Chromium-based browser, any HTTP/2 implementation) or a condition, not one
    installed product, so no product-specific fix can be named for them.
    """
    labels = []
    for row in ignored_rows:
        component = _component_of(row)
        labels.append(_mark(component.display_name if component else row.label))
    names = ", ".join(labels)
    if len(labels) > 1:
        note = (
            f"{names} are generic catalog entries: each stands for a kind of software or "
            f"a condition, not one product installed on the system, so no fix can be named "
            f"for them. Find the products on the affected systems that they refer to (the "
            f"scanner's detection usually names them) and install those products' security "
            f"updates."
        )
    else:
        chrome_example = (
            ", for example Google Chrome or Microsoft Edge for a Chromium-based browser"
            if "Chromium" in names
            else ""
        )
        note = (
            f"{names} is a generic catalog entry: it stands for a kind of software or a "
            f"condition, not one product installed on the system, so no fix can be named for "
            f"it. Find the product on the affected systems that it refers to (the scanner's "
            f"detection usually names it{chrome_example}) and install that product's security "
            f"update."
        )
    if all_ignored:
        what = "those products are" if len(labels) > 1 else "that product is"
        note += f" Until {what} identified, use the compensating controls below."
    return note


def _notes(
    cve: CvePrerequisites,
    targets: tuple[Prerequisite, ...],
    platform_context: tuple[PlatformContext, ...],
    ignored_rows: tuple[Prerequisite, ...] = (),
) -> tuple[str, ...]:
    notes: list[str] = []

    if ignored_rows:
        notes.append(_ignored_note(ignored_rows, all_ignored=not targets))
    elif not targets:
        notes.append(
            "No affected software was named in this record, so only the compensating "
            "controls below are suggested."
        )

    for item in platform_context:
        if item.is_firmware:
            notes.append(
                f"{_mark(item.label)} is appliance software. Its firmware is updated separately "
                f"from the product fix above, on the vendor's own schedule."
            )
        else:
            notes.append(f"Only systems running {_mark(item.label)} are affected.")

    for row in targets:
        if _component_of(row) is None and row.display_id:
            notes.append(
                f"{_mark(row.label)} is not in the component catalog, so it is treated as a "
                f"product update. Confirm the fix with the vendor."
            )

    for row in cve.of_type(PrerequisiteType.PRIVILEGE):
        level = row.parameters.get("privilege_level")
        if level and level != "unauthenticated":
            notes.append(
                f"Exploitation needs {level} access, so keeping those accounts limited "
                f"reduces exposure. It is not a fix on its own."
            )

    for row in cve.of_type(PrerequisiteType.HUMAN_INTERACTION):
        action = row.parameters.get("action") or "interact with"
        target = row.parameters.get("object") or "attacker-supplied content"
        notes.append(
            f"Exploitation needs someone to {action} {target}. User awareness reduces "
            f"the chance of that, but it is not a fix on its own."
        )

    return tuple(notes)
