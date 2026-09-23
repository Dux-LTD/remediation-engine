"""Command line entry point: engine <prerequisite-file> [--json]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # running the file directly
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.prerequisites import load_prerequisites
from engine.suggester import RemediationPlan, suggest


def plan_to_dict(plan: RemediationPlan) -> dict:
    """Machine-readable form of a plan."""
    return {
        "cve_id": plan.cve_id,
        "cvss_score": plan.cvss_score,
        "cvss_vector": plan.cvss_vector,
        "platform_context": [
            {
                "display_id": item.display_id,
                "label": item.label,
                "is_appliance": item.is_appliance,
            }
            for item in plan.platform_context
        ],
        "paths": [
            {
                "target_display_id": path.target_display_id,
                "target_label": path.target_label,
                "layer": path.layer.value,
                "recommended": path.recommended,
                "options": [
                    {
                        "action_id": option.action.id,
                        "title": option.action.title,
                        "description": option.action.description,
                        "detail": option.detail,
                        "condition": option.condition,
                    }
                    for option in path.options
                ],
            }
            for path in plan.paths
        ],
        "notes": list(plan.notes),
    }


def _plain(text: str) -> str:
    """Drop the inline-code markers used by the page."""
    return text.replace("`", "")


def render(plan: RemediationPlan) -> str:
    """Readable form of a plan."""
    lines = [plan.cve_id]
    if plan.cvss_score is not None:
        lines[0] += f" — CVSS {plan.cvss_score}"
    if plan.cvss_vector:
        lines[0] += f" ({plan.cvss_vector})"

    if plan.paths:
        lines.append("")
        lines.append("Any one of these remediations closes this issue on its own.")

    for number, path in enumerate(plan.paths, start=1):
        lines.append("")
        heading = f"{number}. {path.layer.value.title()} — {path.target_label}"
        if path.recommended:
            heading += "  [recommended]"
        lines.append(heading)
        for option in path.options:
            title = option.action.title
            if option.condition:
                title += f" ({option.condition})"
            lines.append(f"   - {title}")
            lines.append(f"     {_plain(option.detail)}")

    if plan.notes:
        lines.append("")
        lines.append("Notes")
        for note in plan.notes:
            lines.append(f"   - {_plain(note)}")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="engine",
        description="Suggest remediation plans for the CVE in a prerequisite file.",
    )
    parser.add_argument("prerequisite_file", type=Path, nargs="*")
    parser.add_argument("--json", action="store_true", help="print machine-readable output")
    parser.add_argument("--ui", action="store_true", help="open a local page instead of printing")
    parser.add_argument("--port", type=int, default=8000, help="port for --ui (default 8000)")
    args = parser.parse_args(argv)

    if args.ui:
        from engine.ui import serve

        serve(port=args.port)
        return 0

    if not args.prerequisite_file:
        parser.error("a prerequisite file is required unless --ui is given")

    plans = [suggest(load_prerequisites(path)) for path in args.prerequisite_file]

    if args.json:
        payload = [plan_to_dict(plan) for plan in plans]
        print(json.dumps(payload if len(payload) > 1 else payload[0], indent=2))
    else:
        print("\n\n".join(render(plan) for plan in plans))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
