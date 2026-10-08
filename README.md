# Remediation engine

Suggests a remediation plan for CVE from its prerequisite file. An example scheme is `engine/prereq_scheme.yaml`.

A plan is a set of alternatives. Any one of them closes the issue on its own. The software fix is currently marked recommended. Configuration and network prerequisites are listed as further alternatives.

## The Engine Process
The entire process is described [here](https://excalidraw.com/#json=FQtHNDEmKDZu8G_yuKGL3,77tuP9VPx9t4ZoiUQ9LVhA)!

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

Open `http://127.0.0.1:8000` and enter the path to a prerequisite file. Each software path shows the affected release lines (supported or end of life), the latest supported version and when the EOL data was fetched. **Show JSON** expands the plan.

## How a plan is built

### Software components

1. **Ignore** components (remediation tag `Ignore`, generic catalog entries such as `chromium-browser`) get no path, only a note.
2. **Whole OS / firmware** (role `os` or `firmware`) next to any other component is context only: the other components are fixed and the OS is named in a note. When only OS / firmware rows remain, each one is a target.
3. **Routing:** remediation tag `OS` → `firmware-update` when the role is `firmware`, otherwise `os-update`. Any other tag → `software-update`. When the OS was set aside as context (step 2), the OS update is worded for "the relevant operating system", with its name when there is one (IE + Windows → "…for the relevant operating system (`Microsoft Windows`)").
4. **Discontinued** products (`DISCONTINUED` in `defs/def_eol.py`, e.g. Flash) → `remove-component` only.
5. **End of life**, for components with an `eol_slug` and versions named in the prerequisite file (exact versions and ranges). Each version is placed on its endoflife.date release line:

| Affected release lines | Options |
|---|---|
| All end of life, a supported line exists | `replace-component` only, naming the latest supported version |
| All end of life, no supported line left | `remove-component` |
| All supported | the update action only |
| Some end of life, some supported | update action + `replace-component` with the condition "if you run the `9.0` or `8.5` line" |
| No version in the file, no `eol_slug`, or no match | update action + conditional `replace-component` (as before) |

6. **Merging:** software paths that give the same fix become one path that names every component. OS / firmware updates with the same options merge (`xorg-server` and `libXfont2` → one OS update), and a product named twice gets one path. A path with an EOL result stays on its own.

The check runs only when every release line of the product is named by digits and dots (`10.1`, `9`). Products whose lines carry any other character (`11-24h2-e`, `r580-linux`, `13.0-sp3`, `subscription`) are skipped, since a version cannot be placed on such a line.

A range whose upper bound is more than one major version above the product's newest release line (macOS `< 2021`, taken from "Security Update 2021-002") is not a product version: it is left out of the check, with a note. Release lines are shown newest first; the text names the affected versions, and the page shows the lines as tags (red for end of life).

EOL data is read live from the endoflife.date API on every suggestion; nothing is cached. Each successful response is saved to `db/eol_last_seen/` and used only when the API cannot be reached; the plan then notes the date of that data. When there is no saved copy either, the plan notes that the status could not be checked.

### Configuration and network

Configuration rows get one option, `configuration-change`. Network rows get one option, `restrict-network-reachability`, worded for the direction in the prerequisite file only (`direction: inbound` → incoming connections, `outbound` → outgoing), and the heading names that direction.

### Static definitions (`defs/`)

| File | Contents |
|---|---|
| `def_components.py` | Generated catalog: role, remediation tag, `eol_slug`, `discontinued` per display_id. Rebuild with `python3 scripts/build_def_components.py`. |
| `def_eol.py` | Component → endoflife.date slug, discontinued products, API URL. No release data. |
| `def_remediation_plans.py` | Every action's title, description, detail template and condition, plus the EOL sentences. |

---

## Current Rules & Gaps

#### OS

1. [no info] Since considered software_component, we have to identify OS cases.
    - OS can affect the suggest remediation (e.g. Active Directory-specific like GPO)
2. In cases of combination of OS+another software_component → treat the software component only for remediation (but note which is the relevant OS refered)
    - Now: role `os` / `firmware` rows are context when another component is present.
3. For OS only → treat it as OS update
    - Now: routing uses the remediation tag and the role (see "How a plan is built").
4. Firmware vs. OS distinction for network appliances/OT - firmware updates may follow a different remediation cadence/rule than general OS patching.
    - Now: role `firmware` → `firmware-update`.
5. [no info] Add explicit handling for EOL/unsupported OS versions (if there is information) - no update exists, so remediation must fall back to compensating controls (isolation, upgrade path) rather than "OS update.”
    - Now: live endoflife.date check for OS products with numeric release lines (macOS, iOS, Android). Windows is skipped (edition-named lines).

### Software Components

1. [no info] Treat the most specific product (for example, we cannot refer for the chromium group because it includes multiple sub-types)
    - Now: Ignore-tagged components get a note asking for the specific product instead of a path.
2. [no info] For non-OS+software component cases → consider treat different plans per OS. (if there is OS → present the OS-related remediation)
    - reason: softwares installed differently across OS (can be services, daemons, binaries etc).
3. For software_component+network_component combinations → the remediation will include OR-based options between software and network (for example: upgrade the software OR make a FW rule)
4. [no info] For software+configuration combinations → if there’s no patch (only misconfiguration), offer remediation for configuration only. 
5. [no info] No-patch / zero-day cases → try config workaround → if there’s no config workaround → define a "compensating control only" remediation category (WAF rule, IDS signature, isolation) distinct from configuration-based mitigation.
6. [no info] EOL software with no vendor support (if there is information) → remediation should default to "replace/upgrade component" rather than "patch.”
    - Now: done for components with an `eol_slug` (see "How a plan is built", step 5).
7. Bundled/transitive dependencies (e.g., a vulnerable library inside a larger application) → remediation should target the specific dependency update path, not the parent application generically, unless only the parent ships a fix.
8. Cloud-native/managed components (e.g., managed DB, SaaS), when vendor-managed solution required → suggest workaround flow (see #5).