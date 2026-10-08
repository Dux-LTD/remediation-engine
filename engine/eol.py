"""Live end-of-life lookups from endoflife.date.

Every lookup calls the API; nothing is cached between lookups, so a new CVE
always sees the current release cycles. After each successful call the
response is written to a last-known-good store. That copy is read only when the
API cannot be reached, and the result then says when it was fetched, so stale
data is never presented as current.

Static definitions (component -> eol_slug, discontinued products, the API URL)
live in defs/def_eol.py. Release cycles, EOL dates and latest versions do not.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

from defs.def_eol import EOL_API_URL

TIMEOUT_SECONDS = 10
# Last-known-good copies: one JSON file per slug. Runtime data, not a definition.
STORE_DIR = Path(
    Path(__file__).resolve().parents[1] / "db" / "eol_last_seen"
)

Fetcher = Callable[[str], dict[str, Any]]


class EolUnavailable(RuntimeError):
    """The API could not be reached and there is no last-seen copy."""


@dataclass(frozen=True, slots=True)
class Release:
    """One release cycle of a product (for example Tomcat 10.1)."""

    name: str
    is_eol: bool
    eol_from: str | None
    latest: str | None
    is_lts: bool
    label: str | None = None

    def display(self, *, beside_lts_word: bool = False) -> str:
        """Name to show a customer. The API label is the display name.

        beside_lts_word drops a trailing "(LTS)" so a sentence that already
        says LTS does not repeat it: "the latest LTS version is 26.04
        'Resolute Raccoon'", not "... (LTS)".
        """
        text = self.label or self.latest or self.name
        if beside_lts_word:
            text = re.sub(r"\s*\((?i:lts)\)\s*$", "", text).strip()
        return text


@dataclass(frozen=True, slots=True)
class ProductReleases:
    """All release cycles of one product, newest first, as the API returned them."""

    slug: str
    releases: tuple[Release, ...]
    fetched_at: str
    live: bool

    def release_for(self, version: str) -> Release | None:
        """The release cycle one version belongs to (longest name match)."""
        version = _normalize(version)
        matches = [
            release
            for release in self.releases
            if version == _normalize(release.name)
            or version.startswith(_normalize(release.name) + ".")
        ]
        return max(matches, key=lambda release: len(release.name), default=None)

    def releases_overlapping(
        self,
        min_version: str | None,
        min_inclusive: bool,
        max_version: str | None,
        max_inclusive: bool,
    ) -> tuple[Release, ...]:
        """Release cycles that contain a version inside this range.

        A cycle such as 10.1 covers 10.1 and 10.1.x. A cycle is included when
        any such version falls inside the range. A shorter cycle is omitted
        when a longer cycle already owns that part of the range (9.0, not 9).
        """
        overlapping = [
            release
            for release in self.releases
            if _overlaps(release.name, min_version, min_inclusive, max_version, max_inclusive)
        ]
        owned = [
            release
            for release in overlapping
            if _owns_part_of_range(
                release,
                overlapping,
                min_version,
                min_inclusive,
                max_version,
                max_inclusive,
            )
        ]
        return tuple(owned)

    @property
    def latest_supported(self) -> Release | None:
        """Newest supported LTS release cycle, or the newest supported one when no LTS."""
        supported = [release for release in self.releases if not release.is_eol]
        return next((release for release in supported if release.is_lts), None) or next(
            iter(supported), None
        )


@dataclass(frozen=True, slots=True)
class EolCheck:
    """EOL status of one installed version."""

    slug: str
    installed_version: str
    release: Release | None
    latest_supported: Release | None
    fetched_at: str
    live: bool

    @property
    def is_eol(self) -> bool | None:
        """True / False when the version maps to a cycle, None when it does not."""
        return None if self.release is None else self.release.is_eol


def fetch_releases(
    slug: str, fetcher: Fetcher | None = None, store_dir: Path | None = None
) -> ProductReleases:
    """Read a product's release cycles live; fall back to last-known-good on failure."""
    store = (store_dir or STORE_DIR) / f"{slug}.json"
    try:
        payload = (fetcher or _http_get)(EOL_API_URL.format(slug=slug))
        releases = _parse(payload)
    except (URLError, OSError, ValueError, KeyError, TypeError) as error:
        return _read_store(slug, store, error)

    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _write_store(store, {"fetched_at": fetched_at, "response": payload})
    return ProductReleases(slug=slug, releases=releases, fetched_at=fetched_at, live=True)


def check(
    slug: str,
    installed_version: str,
    fetcher: Fetcher | None = None,
    store_dir: Path | None = None,
) -> EolCheck:
    """EOL status of an installed version of the product behind `slug`."""
    product = fetch_releases(slug, fetcher=fetcher, store_dir=store_dir)
    return EolCheck(
        slug=slug,
        installed_version=installed_version,
        release=product.release_for(installed_version),
        latest_supported=product.latest_supported,
        fetched_at=product.fetched_at,
        live=product.live,
    )


def _http_get(url: str) -> dict[str, Any]:
    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.load(response)


def _date(value: Any) -> str | None:
    """A calendar date from the API. false and empty mean the date is unknown."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _parse(payload: dict[str, Any]) -> tuple[Release, ...]:
    releases = []
    for entry in payload["result"]["releases"]:
        latest = entry.get("latest") or {}
        label = entry.get("label")
        if not isinstance(label, str) or not label.strip():
            label = latest.get("label") if isinstance(latest, dict) else None
        releases.append(
            Release(
                name=str(entry["name"]),
                is_eol=bool(entry.get("isEol")),
                eol_from=_date(entry.get("eolFrom")),
                latest=latest.get("name") if isinstance(latest, dict) else None,
                is_lts=bool(entry.get("isLts")),
                label=label.strip() if isinstance(label, str) and label.strip() else None,
            )
        )
    if not releases:
        raise ValueError("no releases in response")
    return tuple(releases)


def _read_store(slug: str, store: Path, error: Exception) -> ProductReleases:
    try:
        saved = json.loads(store.read_text(encoding="utf-8"))
        releases = _parse(saved["response"])
    except (OSError, ValueError, KeyError, TypeError):
        raise EolUnavailable(f"endoflife.date unreachable for {slug!r} ({error})") from error
    return ProductReleases(
        slug=slug, releases=releases, fetched_at=saved["fetched_at"], live=False
    )


def _write_store(store: Path, record: dict[str, Any]) -> None:
    try:
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(json.dumps(record), encoding="utf-8")
    except OSError:
        pass  # The fallback copy is best effort; the live answer still stands.


def _normalize(version: str) -> str:
    return re.sub(r"^[vV]", "", version.strip())


def _version_key(version: str) -> tuple[int, ...] | None:
    """Leading numeric components, so 10.1 and v10.1.0 compare as versions."""
    match = re.match(r"\d+(?:\.\d+)*", _normalize(version))
    if not match:
        return None
    return tuple(int(part) for part in match.group(0).split("."))


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    left = left + (0,) * (width - len(left))
    right = right + (0,) * (width - len(right))
    return (left > right) - (left < right)


def _successor(key: tuple[int, ...]) -> tuple[int, ...]:
    """First version that no longer belongs to this release line."""
    return key[:-1] + (key[-1] + 1,)


def _overlaps(
    name: str,
    min_version: str | None,
    min_inclusive: bool,
    max_version: str | None,
    max_inclusive: bool,
) -> bool:
    """True when some version of this release line lies inside the range.

    The line named 10.1 is every version from 10.1 up to, but not including, 10.2.
    """
    key = _version_key(name)
    if key is None:
        return False
    if min_version:
        lower = _version_key(min_version)
        if lower is None or _compare(_successor(key), lower) <= 0:
            return False
    if max_version:
        upper = _version_key(max_version)
        if upper is None:
            return False
        order = _compare(key, upper)
        if order > 0 or (order == 0 and not max_inclusive):
            return False
    return True


def _owns_part_of_range(
    release: Release,
    overlapping: list[Release],
    min_version: str | None,
    min_inclusive: bool,
    max_version: str | None,
    max_inclusive: bool,
) -> bool:
    """False when every overlapping version of this line belongs to a longer line."""
    key = _version_key(release.name)
    if key is None:
        return True
    longer = []
    for other in overlapping:
        other_key = _version_key(other.name)
        if other_key and len(other_key) > len(key) and other_key[: len(key)] == key:
            longer.append(other_key)
    if not longer:
        return True
    # The line still owns a version when the range reaches past those longer lines
    # and stays below the next sibling line.
    ceiling = _successor(key)
    for other_key in longer:
        if min_version:
            lower = _version_key(min_version)
            if lower and _compare(lower, other_key) < 0 and _compare(lower, key) >= 0:
                return True
        else:
            return True
        gap = _successor(other_key)
        if _compare(gap, ceiling) < 0 and (not max_version or _compare(gap, _version_key(max_version) or gap) < 0):
            return True
    return False
