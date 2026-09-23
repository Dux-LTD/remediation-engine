# Remediation engine

Suggests a remediation plan for one CVE from its prerequisite file. The file shape is `engine/prereq_scheme.yaml`.

A plan is a set of alternatives. Any one of them closes the issue on its own. The software fix is marked recommended. Configuration and network prerequisites are listed as further alternatives.

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

Open `http://127.0.0.1:8000` and enter the path to a prerequisite file. **Show JSON** expands the plan. The page listens on localhost only. Stop it with Ctrl+C.
