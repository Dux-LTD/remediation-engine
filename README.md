# Remediation engine

Suggests a remediation plan for CVE from its prerequisite file. An example scheme is `engine/prereq_scheme.yaml`.

A plan is a set of alternatives. Any one of them closes the issue on its own. The software fix is currently marked recommended. Configuration and network prerequisites are listed as further alternatives.

## Setup

Requires Python 3.10+ and [Poetry](https://python-poetry.org/).

```bash
poetry install
```

## Terminal

```bash
poetry run remediate path/to/cve.yaml
poetry run remediate path/to/cve.yaml --json
poetry run remediate a.yaml b.yaml
```

`--json` prints the same plan as one JSON object. Several files print a JSON list.

## Page

```bash
poetry run remediate --ui
poetry run remediate --ui --port 9000
```

Open `http://127.0.0.1:8000` and enter the path to a prerequisite file. **Show JSON** expands the plan.


## Current Rules & Gaps

#### OS

1. [no info] Since considered software_component, we have to identify OS cases.
    - OS can affect the suggest remediation (e.g. Active Directory-specific like GPO)
2. In cases of combination of OS+another software_component → treat the software component only for remediation (but note which is the relevant OS refered)
3. For OS only → treat it as OS update
4. Firmware vs. OS distinction for network appliances/OT - firmware updates may follow a different remediation cadence/rule than general OS patching.
5. [no info] Add explicit handling for EOL/unsupported OS versions (if there is information) - no update exists, so remediation must fall back to compensating controls (isolation, upgrade path) rather than "OS update.”

### Software Components

1. [no info] Treat the most specific product (for example, we cannot refer for the chromium group because it includes multiple sub-types)
2. [no info] For non-OS+software component cases → consider treat different plans per OS. (if there is OS → present the OS-related remediation)
    - reason: softwares installed differently across OS (can be services, daemons, binaries etc).
3. For software_component+network_component combinations → the remediation will include OR-based options between software and network (for example: upgrade the software OR make a FW rule)
4. [no info] For software+configuration combinations → if there’s no patch (only misconfiguration), offer remediation for configuration only. 
5. [no info] No-patch / zero-day cases → try config workaround → if there’s no config workaround → define a "compensating control only" remediation category (WAF rule, IDS signature, isolation) distinct from configuration-based mitigation.
6. [no info] EOL software with no vendor support (if there is information) → remediation should default to "replace/upgrade component" rather than "patch.”
7. Bundled/transitive dependencies (e.g., a vulnerable library inside a larger application) → remediation should target the specific dependency update path, not the parent application generically, unless only the parent ships a fix.
8. Cloud-native/managed components (e.g., managed DB, SaaS), when vendor-managed solution required → suggest workaround flow (see #5).