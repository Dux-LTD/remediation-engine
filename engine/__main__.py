"""Command line entry point: engine <prerequisite-file> [--json]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # running the file directly
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.catalog_lookup import CatalogLookup, CatalogRecordLookup
from engine.prerequisites import PrerequisiteType, load_prerequisites
from engine.suggester import RemediationPlan, suggest


def plan_to_dict(plan: RemediationPlan, catalog: CatalogLookup | None = None) -> dict:
    """Machine-readable form of a plan.

    Catalog record ids are resolved live by (display_id, type). A pair that
    matches two rows contributes null, and the ids are listed under
    catalog_record_conflicts so neither is bound.
    """
    lookup = catalog or CatalogLookup()
    lookup.prepare(_catalog_pairs(plan))
    return {
        "cve_id": plan.cve_id,
        "cvss_score": plan.cvss_score,
        "cvss_vector": plan.cvss_vector,
        "platform_context": [
            _platform_to_dict(item, lookup) for item in plan.platform_context
        ],
        "paths": [
            {
                "record_ids": list(path.record_ids),
                "target_display_ids": list(path.target_display_ids or (path.target_display_id,)),
                **_catalog_fields(
                    lookup,
                    path.target_display_ids or (path.target_display_id,),
                    path.catalog_type,
                ),
                "target_label": path.target_label,
                "layer": path.layer.value,
                "recommended": path.recommended,
                "eol": _eol_to_dict(path.eol),
                "options": [
                    {
                        "action_id": option.action.id,
                        "title": option.action.title,
                        "description": option.action.description,
                        "detail": option.detail,
                        "detail_parts": list(option.detail_parts or (option.detail,)),
                        "condition": option.condition,
                        "eol_lines": list(option.eol_lines),
                    }
                    for option in path.options
                ],
            }
            for path in plan.paths
        ],
        "notes": list(plan.notes),
    }


def _catalog_pairs(plan: RemediationPlan) -> list[tuple[str, PrerequisiteType]]:
    """Every (display_id, type) the JSON will resolve, so one scan serves them all."""
    pairs: list[tuple[str, PrerequisiteType]] = []
    for item in plan.platform_context:
        if item.catalog_type is not None:
            pairs.append((item.display_id, item.catalog_type))
    for path in plan.paths:
        if path.catalog_type is None:
            continue
        display_ids = path.target_display_ids or (path.target_display_id,)
        pairs.extend((display_id, path.catalog_type) for display_id in display_ids)
    return pairs


def _platform_to_dict(item, lookup: CatalogLookup) -> dict:
    found = _find(lookup, item.display_id, item.catalog_type)
    payload = {
        "display_id": item.display_id,
        "catalog_record_id": found.record_id,
        "label": item.label,
        "is_firmware": item.is_firmware,
    }
    if len(found.ids) > 1:
        payload["catalog_record_conflicts"] = list(found.ids)
    return payload


def _catalog_fields(
    lookup: CatalogLookup,
    display_ids: tuple[str, ...],
    catalog_type: PrerequisiteType | None,
) -> dict:
    """One catalog id per display id. Null when the pair is missing or duplicated."""
    ids: list[str | None] = []
    conflicts = []
    for display_id in display_ids:
        found = _find(lookup, display_id, catalog_type)
        ids.append(found.record_id)
        if len(found.ids) > 1:
            conflicts.append(
                {"display_id": display_id, "type": found.type, "ids": list(found.ids)}
            )
    fields: dict = {"catalog_record_ids": ids}
    if conflicts:
        fields["catalog_record_conflicts"] = conflicts
    return fields


def _find(
    lookup: CatalogLookup, display_id: str, catalog_type: PrerequisiteType | None
) -> CatalogRecordLookup:
    if catalog_type is None:
        return CatalogRecordLookup(display_id, "", ())
    return lookup.find(display_id, catalog_type)


def _eol_to_dict(eol) -> dict | None:
    """Live EOL check behind a software path, when one ran."""
    if eol is None:
        return None
    return {
        "slug": eol.slug,
        "exact_versions": list(eol.exact_versions),
        "ranges": [
            {
                "min": {"version": span.min.version, "inclusive": span.min.inclusive} if span.min else None,
                "max": {"version": span.max.version, "inclusive": span.max.inclusive} if span.max else None,
            }
            for span in eol.ranges
        ],
        "lines": [
            {"name": line.name, "is_eol": line.is_eol, "eol_from": line.eol_from, "inferred": line.inferred}
            for line in eol.lines
        ],
        "unmatched_exact": list(eol.unmatched_exact),
        "all_eol": eol.all_eol,
        "latest_supported": eol.latest_supported.display() if eol.latest_supported else None,
        "latest_supported_is_lts": bool(eol.latest_supported and eol.latest_supported.is_lts),
        "fetched_at": eol.fetched_at,
        "live": eol.live,
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
                eol_names = f": {', '.join(option.eol_lines)}" if option.eol_lines else ""
                title += f" ({_plain(option.condition)}{eol_names})"
            lines.append(f"   - {title}")
            parts = option.detail_parts or (option.detail,)
            if len(parts) > 1:
                lines.extend(f"     • {_plain(part)}" for part in parts)
            else:
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
        catalog = CatalogLookup()
        payload = [plan_to_dict(plan, catalog) for plan in plans]
        print(json.dumps(payload if len(payload) > 1 else payload[0], indent=2))
    else:
        print("\n\n".join(render(plan) for plan in plans))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
