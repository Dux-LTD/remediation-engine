"""General remediation actions a customer can take.

Software, configuration, and network-layer actions only. This file is the
single source for every customer-facing word of an action: its title, its
description, and the detail template the engine fills for a specific CVE.

Detail placeholders (the engine fills them; names arrive already marked):
  software       {name} component name, {platform} platform sentence or "",
                 {eol} end-of-life sentence (EOL_SENTENCES) or "",
                 {its} "its", or "their" when a path covers several components,
                 {os} " (`OS name`)" when exactly one OS was set aside as context, or ""
  configuration  {name} setting name, {state} state sentence or ""
  network        {service} network service name
"""

from dataclasses import dataclass
from enum import Enum


class ActionCategory(Enum):
    """Where the remediation is applied."""

    SOFTWARE = "software"
    CONFIGURATION = "configuration"
    NETWORK = "network"


@dataclass(frozen=True, slots=True)
class RemediationAction:
    """One remediation a customer can carry out.

    detail           template for one CVE (see placeholders above)
    detail_outbound  network actions only: template when the vulnerable side
                     opens the connection (direction = outbound)
    detail_on_platform  software actions only: template when the CVE's operating
                     system was set aside as context (rule 5), so the update
                     is for that operating system, not the named component
    condition        when the option applies, if not always
    """

    id: str
    title: str
    description: str
    category: ActionCategory
    detail: str
    detail_outbound: str | None = None
    condition: str | None = None
    detail_on_platform: str | None = None


SOFTWARE_ACTIONS: tuple[RemediationAction, ...] = (
    RemediationAction(
        "os-update",
        "Install the latest operating system update",
        "Install the latest update your operating system vendor has published.",
        ActionCategory.SOFTWARE,
        detail="Install the latest operating system update for {name} on every affected system.{eol}",
        detail_on_platform="Install the latest operating system update for the relevant operating system{os} on every affected system.{eol}",
    ),
    RemediationAction(
        "firmware-update",
        "Install the latest device firmware",
        "Install the latest firmware release from the device vendor. Network appliances and industrial devices are updated on their own schedule, separate from desktop and server operating system patches.",
        ActionCategory.SOFTWARE,
        detail="Install the latest firmware release the vendor published for {name}.{eol}",
    ),
    RemediationAction(
        "software-update",
        "Install the latest product version",
        "Install the latest version the product vendor has published.",
        ActionCategory.SOFTWARE,
        detail="Install the latest version of {name}.{platform}{eol}",
    ),
    RemediationAction(
        "replace-component",
        "Replace with the latest version",
        "Replace the software with its latest version (the latest LTS release when there is one). Use this when the installed version is no longer supported and gets no fix.",
        ActionCategory.SOFTWARE,
        detail="Replace {name} with {its} latest version, or the latest LTS release when there is one.{eol}",
        condition="if this version is no longer supported and the vendor has published no fix",
    ),
    RemediationAction(
        "remove-component",
        "Remove the unsupported product",
        "Remove the product. The vendor no longer supports it and no newer version exists.",
        ActionCategory.SOFTWARE,
        detail="Remove {name} from every affected system. The vendor no longer supports it and has no newer version to move to.{eol}",
    ),
)

# End-of-life sentences for {eol}. {subject} names the affected versions
# (one exact version, several exact versions, or a range). The release lines
# themselves are not listed in the text: the page shows them as tags.
# {until} is EOL_UNTIL or "" — the date standard support ends for the latest
# supported release (endoflife.date eolFrom).
EOL_SENTENCES: dict[str, str] = {
    "eol": " {subject} at end of life. The {latest_kind} is {latest}{until}, according to {date}.",
    "eol_no_successor": " {subject} at end of life, and no supported release line is left.",
    "supported": " {subject} supported. The {latest_kind} is {latest}{until}, according to {date}.",
    "mixed": " {subject} on both end-of-life and supported release lines. The {latest_kind} is {latest}{until}, according to {date}.",
    # Replace option of a mixed result: the mixed sentence is on the update
    # option already, and the option lists the end-of-life lines it applies to.
    "mixed_replace": " The {latest_kind} is {latest}{until}, according to {date}.",
}
# Condition of the replace option when only some affected lines are end of
# life. The option's eol_lines name those lines; the page shows them as tags.
EOL_CONDITION = "if you run one of these end-of-life lines"
# How the target in {latest_kind} is named: an LTS line is recommended as such.
EOL_LATEST_KIND: dict[bool, str] = {True: "latest supported LTS version", False: "latest supported version"}
EOL_UNTIL = ", supported until {date}"

CONFIGURATION_ACTIONS: tuple[RemediationAction, ...] = (
    RemediationAction(
        "configuration-change",
        "Configuration change",
        "Change the vulnerable setting to a supported value that is not affected, or turn the feature off where it is not needed.",
        ActionCategory.CONFIGURATION,
        detail="Change {name} configuration to a supported setting that is not affected, or turn it off on systems that do not need it.{state}",
    ),
)

NETWORK_ACTIONS: tuple[RemediationAction, ...] = (
    RemediationAction(
        "restrict-network-reachability",
        "Restrict service network reachability",
        "Limit network access to the affected service so only the systems that need it can use it, and block it from everything else, including the Internet.",
        ActionCategory.NETWORK,
        detail="Accept incoming {service} connections on the affected systems only from the systems that need them.",
        detail_outbound="Let the affected systems open outgoing {service} connections only to destinations you trust.",
    ),
)

REMEDIATION_ACTIONS: tuple[RemediationAction, ...] = (
    *SOFTWARE_ACTIONS,
    *CONFIGURATION_ACTIONS,
    *NETWORK_ACTIONS,
)

ACTIONS_BY_ID: dict[str, RemediationAction] = {
    action.id: action for action in REMEDIATION_ACTIONS
}


def render_detail(
    action: RemediationAction, outbound: bool = False, on_platform: bool = False, **values: str
) -> str:
    """Fill an action's detail template for one CVE."""
    template = action.detail
    if outbound and action.detail_outbound:
        template = action.detail_outbound
    if on_platform and action.detail_on_platform:
        template = action.detail_on_platform
    return template.format(**values)


# Network path heading: the service and the direction of the connection.
NETWORK_DIRECTION_WORDS: dict[str, str] = {"inbound": "incoming", "outbound": "outgoing"}
NETWORK_TARGET_LABEL = "{service} ({direction})"
