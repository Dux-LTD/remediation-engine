"""Turns the prerequisites of one CVE into remediation suggestions.

A CVE is exploitable only when all of its prerequisites hold, so removing any
single one of them remediates it. The engine therefore returns alternative
paths: each path on its own closes the issue, and the customer picks one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from defs.def_components import RemediationTag, Role, SOFTWARE_COMPONENTS, SoftwareComponent
from defs.def_remediation_plans import (
    ActionCategory,
    CONFIGURATION_ACTIONS,
    NETWORK_ACTIONS,
    REMEDIATION_ACTIONS,
    RemediationAction,
)

from .prerequisites import CvePrerequisites, Prerequisite, PrerequisiteType

def _catalog_key(text: str) -> str:
    """Normalize a display name or kebab id for catalog lookup."""
    return re.sub(r"[^a-z0-9]+", "-", text.casefold()).strip("-")


COMPONENTS_BY_ID: dict[str, SoftwareComponent] = dict(SOFTWARE_COMPONENTS)  # by display_id
for _component in SOFTWARE_COMPONENTS.values():
    COMPONENTS_BY_ID.setdefault(_component.display_name, _component)
    COMPONENTS_BY_ID.setdefault(_catalog_key(_component.display_name), _component)
ACTIONS_BY_ID: dict[str, RemediationAction] = {
    action.id: action for action in REMEDIATION_ACTIONS
}

# Roles that mean "the whole OS or firmware itself" (logic v2, rule 5).
WHOLE_OS_ROLES = frozenset({Role.OS, Role.FIRMWARE})

# One line per network action, per direction of the connection.
NETWORK_DETAILS: dict[str, tuple[str, str]] = {
    "firewall-allow-restricted": (
        "Keep `{service}` reachable only from the systems that need it, and close it to everything else.",
        "Allow `{service}` out only to the destinations you trust, and close it to everything else.",
    ),
    "firewall-block": (
        "Block incoming `{service}` traffic to the affected systems at the network firewall.",
        "Block outgoing `{service}` traffic from the affected systems at the network firewall.",
    ),
    "host-firewall-rule": (
        "Add a rule on the affected systems themselves that refuses incoming `{service}` traffic from anyone who does not need it.",
        "Add a rule on the affected systems themselves that stops them from opening `{service}` connections you have not approved.",
    ),
    "firewall-identity": (
        "Allow incoming `{service}` only for named administrators or the specific users who need it.",
        "Allow outgoing `{service}` only for the named accounts or services that need it.",
    ),
    "acl-rule": (
        "Add an access rule on the router or switch so only approved networks can reach `{service}`.",
        "Add an access rule on the router or switch so the affected systems can reach `{service}` only where needed.",
    ),
    "network-segmentation": (
        "Move the affected systems to their own network segment or VLAN, so `{service}` is reachable only from approved systems.",
        "Move the affected systems to their own network segment or VLAN, so their `{service}` traffic stays inside a controlled path.",
    ),
    "reduce-network-exposure": (
        "Take `{service}` off the Internet and any other untrusted network, so it is reachable only internally.",
        "Send `{service}` traffic through an approved proxy or gateway instead of letting the systems reach the Internet directly.",
    ),
}

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


@dataclass(frozen=True, slots=True)
class PlatformContext:
    """Operating system a CVE is scoped to, when the fix is in a product on it."""

    display_id: str
    label: str
    is_firmware: bool


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    """The suggestion for one CVE."""

    cve_id: str
    paths: tuple[RemediationPath, ...]
    platform_context: tuple[PlatformContext, ...] = ()
    notes: tuple[str, ...] = ()
    cvss_score: float | None = None
    cvss_vector: str | None = None


def suggest(cve: CvePrerequisites) -> RemediationPlan:
    """Suggest remediation paths for one CVE."""
    software_rows = cve.of_type(PrerequisiteType.SOFTWARE_COMPONENT)
    targets, platform_rows, ignored_rows = _split_software_rows(software_rows)
    platform_context = tuple(_platform_context(row) for row in platform_rows)

    paths: list[RemediationPath] = []
    for row in targets:
        paths.append(_software_path(row, platform_context))
    for row in cve.of_type(PrerequisiteType.CONFIGURATION):
        paths.append(_configuration_path(row))
    for row in cve.of_type(PrerequisiteType.NETWORK_SERVICE):
        paths.append(_network_path(row))

    return RemediationPlan(
        cve_id=cve.cve_id,
        paths=tuple(paths),
        platform_context=platform_context,
        notes=_notes(cve, targets, platform_context, ignored_rows),
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


def _version_sentence(row: Prerequisite) -> str:
    fixed = row.fixed_version
    if fixed:
        return f"Move to version {_mark(fixed)} or later."
    return "Use the fixed version named in the vendor advisory."


def _platform_sentence(platform_context: tuple[PlatformContext, ...]) -> str:
    if not platform_context:
        return ""
    names = ", ".join(_mark(item.label) for item in platform_context)
    return f" This applies to the affected systems running {names}."


def _software_path(
    row: Prerequisite, platform_context: tuple[PlatformContext, ...]
) -> RemediationPath:
    component = _component_of(row)
    name = _mark(row.label)
    version = _version_sentence(row)
    platform = _platform_sentence(platform_context)

    # Logic v2 routing: the remediation tag decides OS/firmware update vs vendor
    # patch; the role decides firmware vs OS update.
    if component is not None and component.remediation_tag is RemediationTag.OS:
        if component.role is Role.FIRMWARE:
            action_id = "firmware-update"
            detail = (
                f"Install the firmware release the vendor published for {name}. "
                f"Appliance and operational technology firmware is released on its own "
                f"schedule, so it is not covered by regular server and desktop patching. {version}"
            )
        else:
            action_id = "os-update"
            detail = (
                f"Install the operating system security update for {name} on every "
                f"affected system. {version}"
            )
    else:
        action_id = "software-update"
        detail = f"Install the security update the vendor published for {name}. {version}{platform}"

    options = [RemediationOption(ACTIONS_BY_ID[action_id], detail)]
    options.append(
        RemediationOption(
            ACTIONS_BY_ID["replace-component"],
            f"Move to a supported version of {name}, or to a product that replaces it.",
            condition="if this version is no longer supported and the vendor has published no fix",
        )
    )
    return RemediationPath(
        target_display_id=row.display_id,
        target_label=row.label,
        layer=ActionCategory.SOFTWARE,
        options=tuple(options),
        recommended=True,
    )


def _configuration_path(row: Prerequisite) -> RemediationPath:
    name = _mark(_configuration_name(row.label))
    value = row.required_value
    state = f" The issue applies while it is set to {_mark(value)}." if value else ""
    if row.vulnerable_by_default:
        state += " This is the default setting, so it is likely in place."

    options = []
    for action in CONFIGURATION_ACTIONS:
        if action.id == "configuration-hardening":
            detail = f"Change {name} configuration to a supported setting that is not affected.{state}"
        else:
            detail = f"Turn off or remove {name} configuration on systems that do not need it.{state}"
        options.append(RemediationOption(action, detail))

    return RemediationPath(
        target_display_id=row.display_id,
        target_label=row.label,
        layer=ActionCategory.CONFIGURATION,
        options=tuple(options),
    )


def _network_path(row: Prerequisite) -> RemediationPath:
    service = row.label
    outbound = row.direction == "outbound"
    index = 1 if outbound else 0

    options = tuple(
        RemediationOption(action, NETWORK_DETAILS[action.id][index].format(service=service))
        for action in NETWORK_ACTIONS
        if action.id in NETWORK_DETAILS
    )
    return RemediationPath(
        target_display_id=row.display_id,
        target_label=service,
        layer=ActionCategory.NETWORK,
        options=options,
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
