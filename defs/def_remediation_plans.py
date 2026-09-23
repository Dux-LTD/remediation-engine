"""General remediation actions a customer can take.

Software, configuration, and network-layer actions only. Titles and
descriptions are written for the customer.
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
    """One remediation a customer can carry out."""

    id: str
    title: str
    description: str
    category: ActionCategory


SOFTWARE_ACTIONS: tuple[RemediationAction, ...] = (
    RemediationAction(
        "os-update",
        "Install the operating system security update",
        "Apply the security update your operating system vendor published for this issue.",
        ActionCategory.SOFTWARE,
    ),
    RemediationAction(
        "firmware-update",
        "Update the device firmware",
        "Install the firmware release from the device vendor. Network appliances and industrial devices are updated on their own schedule, separate from desktop and server operating system patches.",
        ActionCategory.SOFTWARE,
    ),
    RemediationAction(
        "software-update",
        "Install the product security update",
        "Apply the patch or update the product vendor published. This updates the affected product itself.",
        ActionCategory.SOFTWARE,
    ),
    RemediationAction(
        "dependency-update",
        "Update the vulnerable library",
        "Upgrade the specific library or package that contains the vulnerability. The application that uses it stays as it is.",
        ActionCategory.SOFTWARE,
    ),
    RemediationAction(
        "replace-component",
        "Replace the unsupported software",
        "Move to a supported version or product. No security patch is available because the vendor no longer supports this software.",
        ActionCategory.SOFTWARE,
    ),
)

CONFIGURATION_ACTIONS: tuple[RemediationAction, ...] = (
    RemediationAction(
        "configuration-hardening",
        "Change a setting to close the exposure",
        "Apply the vendor-supported configuration change that mitigates this issue. Use this when no patch is available and a setting fully addresses it.",
        ActionCategory.CONFIGURATION,
    ),
    RemediationAction(
        "disable-feature",
        "Turn off the unused feature",
        "Disable or remove the vulnerable feature, protocol, or component if you do not need it.",
        ActionCategory.CONFIGURATION,
    ),
)

NETWORK_ACTIONS: tuple[RemediationAction, ...] = (
    RemediationAction(
        "firewall-allow-restricted",
        "Allow only required network access",
        "Keep the service reachable, and limit which sources, destinations, ports, or protocols can use it.",
        ActionCategory.NETWORK,
    ),
    RemediationAction(
        "firewall-block",
        "Block access at the network firewall",
        "Deny traffic to the affected service so it cannot be reached through the network firewall.",
        ActionCategory.NETWORK,
    ),
    RemediationAction(
        "host-firewall-rule",
        "Restrict access on the device firewall",
        "Apply an allow or block rule on the device itself, so access stays limited even if the network firewall changes.",
        ActionCategory.NETWORK,
    ),
    RemediationAction(
        "firewall-identity",
        "Limit access to approved people",
        "Allow the firewall rule only for the administrators or other people who need this access.",
        ActionCategory.NETWORK,
    ),
    RemediationAction(
        "acl-rule",
        "Add a router or switch access rule",
        "Restrict traffic on the router or switch by source, destination, port, or protocol.",
        ActionCategory.NETWORK,
    ),
    RemediationAction(
        "network-segmentation",
        "Isolate the asset on its own network",
        "Move the asset to a separate VLAN or network segment so only approved systems can reach it.",
        ActionCategory.NETWORK,
    ),
    RemediationAction(
        "reduce-network-exposure",
        "Remove access from the Internet",
        "Take the interface or service off the Internet and other untrusted networks, so it is reachable only from your internal network.",
        ActionCategory.NETWORK,
    ),
)

REMEDIATION_ACTIONS: tuple[RemediationAction, ...] = (
    *SOFTWARE_ACTIONS,
    *CONFIGURATION_ACTIONS,
    *NETWORK_ACTIONS,
)
