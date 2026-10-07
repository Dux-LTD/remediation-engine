"""General remediation actions a customer can take.

Software, configuration, and network-layer actions only. This file is the
single source for every customer-facing word of an action: its title, its
description, and the detail template the engine fills for a specific CVE.

Detail placeholders (the engine fills them; names arrive already marked):
  software       {name} component name, {platform} platform sentence or ""
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
    condition        when the option applies, if not always
    """

    id: str
    title: str
    description: str
    category: ActionCategory
    detail: str
    detail_outbound: str | None = None
    condition: str | None = None


SOFTWARE_ACTIONS: tuple[RemediationAction, ...] = (
    RemediationAction(
        "os-update",
        "Install the latest operating system update",
        "Install the latest update your operating system vendor has published.",
        ActionCategory.SOFTWARE,
        detail="Install the latest operating system update for {name} on every affected system.",
    ),
    RemediationAction(
        "firmware-update",
        "Install the latest device firmware",
        "Install the latest firmware release from the device vendor. Network appliances and industrial devices are updated on their own schedule, separate from desktop and server operating system patches.",
        ActionCategory.SOFTWARE,
        detail="Install the latest firmware release the vendor published for {name}.",
    ),
    RemediationAction(
        "software-update",
        "Install the latest product version",
        "Install the latest version the product vendor has published.",
        ActionCategory.SOFTWARE,
        detail="Install the latest version of {name}.{platform}",
    ),
    RemediationAction(
        "replace-component",
        "Replace with the latest version",
        "Replace the software with its latest version (the latest LTS release when there is one). Use this when the installed version is no longer supported and gets no fix.",
        ActionCategory.SOFTWARE,
        detail="Replace {name} with its latest version, or the latest LTS release when there is one.",
        condition="if this version is no longer supported and the vendor has published no fix",
    ),
    RemediationAction(
        "remove-component",
        "Remove the unsupported product",
        "Remove the product. The vendor no longer supports it and no newer version exists.",
        ActionCategory.SOFTWARE,
        detail="Remove {name} from every affected system. The vendor no longer supports it and has no newer version to move to.",
    ),
)

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
        "firewall-allow-restricted",
        "Allow only required network access",
        "Keep the service reachable, and limit which sources, destinations, ports, or protocols can use it.",
        ActionCategory.NETWORK,
        detail="Keep {service} reachable only from the systems that need it, and close it to everything else.",
        detail_outbound="Allow {service} out only to the destinations you trust, and close it to everything else.",
    ),
    RemediationAction(
        "firewall-block",
        "Block access at the network firewall",
        "Deny traffic to the affected service so it cannot be reached through the network firewall.",
        ActionCategory.NETWORK,
        detail="Block incoming {service} traffic to the affected systems at the network firewall.",
        detail_outbound="Block outgoing {service} traffic from the affected systems at the network firewall.",
    ),
    RemediationAction(
        "host-firewall-rule",
        "Restrict access on the device firewall",
        "Apply an allow or block rule on the device itself, so access stays limited even if the network firewall changes.",
        ActionCategory.NETWORK,
        detail="Add a rule on the affected systems themselves that refuses incoming {service} traffic from anyone who does not need it.",
        detail_outbound="Add a rule on the affected systems themselves that stops them from opening {service} connections you have not approved.",
    ),
    RemediationAction(
        "firewall-identity",
        "Limit access to approved people",
        "Allow the firewall rule only for the administrators or other people who need this access.",
        ActionCategory.NETWORK,
        detail="Allow incoming {service} only for named administrators or the specific users who need it.",
        detail_outbound="Allow outgoing {service} only for the named accounts or services that need it.",
    ),
    RemediationAction(
        "acl-rule",
        "Add a router or switch access rule",
        "Restrict traffic on the router or switch by source, destination, port, or protocol.",
        ActionCategory.NETWORK,
        detail="Add an access rule on the router or switch so only approved networks can reach {service}.",
        detail_outbound="Add an access rule on the router or switch so the affected systems can reach {service} only where needed.",
    ),
    RemediationAction(
        "network-segmentation",
        "Isolate the asset on its own network",
        "Move the asset to a separate VLAN or network segment so only approved systems can reach it.",
        ActionCategory.NETWORK,
        detail="Move the affected systems to their own network segment or VLAN, so {service} is reachable only from approved systems.",
        detail_outbound="Move the affected systems to their own network segment or VLAN, so their {service} traffic stays inside a controlled path.",
    ),
    RemediationAction(
        "reduce-network-exposure",
        "Remove access from the Internet",
        "Take the interface or service off the Internet and other untrusted networks, so it is reachable only from your internal network.",
        ActionCategory.NETWORK,
        detail="Take {service} off the Internet and any other untrusted network, so it is reachable only internally.",
        detail_outbound="Send {service} traffic through an approved proxy or gateway instead of letting the systems reach the Internet directly.",
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


def render_detail(action: RemediationAction, outbound: bool = False, **values: str) -> str:
    """Fill an action's detail template for one CVE."""
    template = action.detail_outbound if outbound and action.detail_outbound else action.detail
    return template.format(**values)
