"""Resolve a catalog record UUID from the pair (display_id, type).

There is no lookup-by-name endpoint. GET /catalog/ is paged, and each row is
matched with exact string equality on display_id and type. reviewed is not
sent: an unreviewed row still owns the pair.

Paging stops once every requested name has a row. A second row on a page
already fetched is returned and neither id is chosen. A name that never
appears is reported only after the remaining pages are read.

Each wave of pages runs together, one thread per page.
"""

from __future__ import annotations

import json
import math
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .prerequisites import PrerequisiteType

DEFAULT_BASE_URL = "https://internal.dux.io/threat-research"
DEFAULT_TENANT_ID = "c58ebe00-3c64-4fd5-81f5-a08abcb9b7a2"
DESCOPE_EXCHANGE_URL = "https://api.descope.com/v1/auth/accesskey/exchange"
PAGE_SIZE = 100
# Pages fetched together. The next wave starts only if a requested name is still missing.
PAGE_WORKERS = 16
TIMEOUT_SECONDS = 30
# Cloudflare rejects urllib's default User-Agent (error 1010). This matches the
# Descope SDK headers the uploaders send on the access-key exchange.
_DESCOPE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "dux-remediation/1.0",
    "x-descope-sdk-name": "python",
}

# The catalog type query is the prerequisite type label from local code.
FETCH_TYPES = frozenset(
    {
        PrerequisiteType.SOFTWARE_COMPONENT,
        PrerequisiteType.CONFIGURATION,
        PrerequisiteType.NETWORK_SERVICE,
    }
)


class CatalogLookupError(RuntimeError):
    """The catalog could not be queried, or the response was not usable."""


@dataclass(frozen=True, slots=True)
class CatalogRecordLookup:
    """Ids of the rows whose (display_id, type) pair matched.

    One id is the catalog_record_id. None means the name is free. Two or more
    is a data error: record_id stays empty so neither id is bound.
    """

    display_id: str
    type: str
    ids: tuple[str, ...]

    @property
    def record_id(self) -> str | None:
        if len(self.ids) == 1:
            return self.ids[0]
        return None


@dataclass
class _TypeScan:
    """Rows of one catalog type already read, and the next page still to fetch."""

    index: dict[str, list[str]]
    next_page: int = 1
    total_pages: int | None = None
    done: bool = False


class CatalogLookup:
    """Pages GET /catalog/?type= and remembers rows already read."""

    def __init__(self, base_url: str | None = None, tenant_id: str | None = None) -> None:
        configured = base_url if base_url is not None else os.environ.get("THREAT_RESEARCH_BASE_URL")
        self.base_url = (configured or DEFAULT_BASE_URL).rstrip("/")
        self.tenant_id = tenant_id or DEFAULT_TENANT_ID
        self._scans: dict[str, _TypeScan] = {}
        self._jwt: str | None = None
        self._skip_env_bearer = False
        self._refreshed = False
        self._auth_lock = threading.Lock()

    def find(self, display_id: str, record_type: PrerequisiteType) -> CatalogRecordLookup:
        """The catalog rows for this pair. Exact match, no case folding.

        record_type is the local prerequisite label: software_component,
        configuration, or network_service. That label is the type query.

        Paging for that type stops once this name has a row. Names resolved
        together share those pages.
        """
        if record_type not in FETCH_TYPES:
            labels = sorted(item.value for item in FETCH_TYPES)
            raise CatalogLookupError(
                f"catalog type {record_type.value!r} is not one of {labels}"
            )
        type_label = record_type.value
        if not display_id:
            return CatalogRecordLookup(display_id, type_label, ())
        self.prepare([(display_id, record_type)])
        scan = self._scans[type_label]
        return CatalogRecordLookup(display_id, type_label, tuple(scan.index.get(display_id, ())))

    def prepare(self, pairs: list[tuple[str, PrerequisiteType]]) -> None:
        """Fetch until every pair has a row, or that type's pages run out."""
        grouped: dict[str, set[str]] = {}
        for display_id, record_type in pairs:
            if not display_id or record_type not in FETCH_TYPES:
                continue
            grouped.setdefault(record_type.value, set()).add(display_id)
        for type_label, names in grouped.items():
            scan = self._scans.setdefault(type_label, _TypeScan(index={}))
            pending = {name for name in names if not scan.index.get(name)}
            if pending and not scan.done:
                self._seek(scan, type_label, pending)

    def _seek(self, scan: _TypeScan, record_type: str, wanted: set[str]) -> None:
        self._session_jwt()
        while wanted and not scan.done:
            if scan.total_pages is not None and scan.next_page > scan.total_pages:
                scan.done = True
                break
            # The first page carries total, so later waves do not run past the end.
            if scan.total_pages is None:
                batch = [scan.next_page]
            else:
                last = min(scan.total_pages, scan.next_page + PAGE_WORKERS - 1)
                batch = list(range(scan.next_page, last + 1))
            if not batch:
                scan.done = True
                break
            fetched = self._fetch_pages(record_type, batch)
            for page in batch:
                items, total = fetched[page]
                for item in items:
                    _collect(scan.index, item, record_type)
                if isinstance(total, int):
                    scan.total_pages = _page_count(total)
                if not items:
                    scan.done = True
            scan.next_page = batch[-1] + 1
            wanted = {name for name in wanted if not scan.index.get(name)}

    def _fetch_pages(
        self, record_type: str, pages: list[int]
    ) -> dict[int, tuple[list[Any], Any]]:
        if len(pages) == 1:
            return {pages[0]: self._fetch_items(record_type, pages[0])}
        found: dict[int, tuple[list[Any], Any]] = {}
        with ThreadPoolExecutor(max_workers=len(pages)) as pool:
            futures = {
                pool.submit(self._fetch_items, record_type, page): page for page in pages
            }
            for future, page in futures.items():
                found[page] = future.result()
        return found

    def _fetch_items(self, record_type: str, page: int) -> tuple[list[Any], Any]:
        payload = self._get_page(record_type, page)
        items = payload.get("items")
        if not isinstance(items, list):
            raise CatalogLookupError(f"catalog page {page} for {record_type} has no items list")
        return items, payload.get("total")

    def _get_page(self, record_type: str, page: int) -> dict[str, Any]:
        query = urlencode({"type": record_type, "page": page, "size": PAGE_SIZE})
        url = f"{self.base_url}/catalog/?{query}"
        token = self._session_jwt()
        try:
            return self._get_json(url, token)
        except HTTPError as exc:
            if exc.code != 401:
                raise CatalogLookupError(_http_message(exc)) from exc
            try:
                return self._get_json(url, self._refresh_session(token))
            except HTTPError as again:
                raise CatalogLookupError(_http_message(again)) from again

    def _refresh_session(self, rejected: str) -> str:
        """One new session after a 401. Later callers share that session."""
        with self._auth_lock:
            if self._jwt and self._jwt != rejected:
                return self._jwt
            if self._refreshed:
                raise CatalogLookupError("catalog returned HTTP 401")
            self._refreshed = True
            self._jwt = None
            self._skip_env_bearer = True
            return self._session_jwt()

    def _session_jwt(self) -> str:
        if self._jwt:
            return self._jwt
        bearer = os.environ.get("NETWORK_ANALYSIS_BEARER_TOKEN", "").strip()
        if not self._skip_env_bearer and _is_jwt(bearer):
            self._jwt = bearer
            return bearer
        self._jwt = _exchange_machine_token()
        return self._jwt

    def _get_json(self, url: str, token: str) -> dict[str, Any]:
        request = Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Selected-Tenant": self.tenant_id,
                "Accept": "application/json",
                "User-Agent": "dux-remediation/1.0",
            },
        )
        try:
            with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                body = json.loads(response.read().decode("utf-8"))
        except HTTPError:
            raise
        except (URLError, TimeoutError, json.JSONDecodeError, UnicodeError) as exc:
            raise CatalogLookupError(f"catalog request failed: {exc}") from exc
        if not isinstance(body, dict):
            raise CatalogLookupError("catalog response was not a JSON object")
        return body


def _page_count(total: int) -> int:
    """How many pages cover this many rows."""
    if total <= 0:
        return 1
    return math.ceil(total / PAGE_SIZE)


def _collect(index: dict[str, list[str]], item: Any, record_type: str) -> None:
    """Keep a row when both fields equal the pair. Same id is not stored twice."""
    if not isinstance(item, dict):
        return
    if item.get("type") != record_type:
        return
    display_id = item.get("display_id")
    record_id = item.get("id")
    if not isinstance(display_id, str) or not isinstance(record_id, str):
        return
    found = index.setdefault(display_id, [])
    if record_id not in found:
        found.append(record_id)


def _is_jwt(token: str) -> bool:
    """A session JWT has three non-empty dot-separated segments. A placeholder does not."""
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def _exchange_machine_token() -> str:
    """Descope access-key exchange. Used when the env bearer is not a real JWT."""
    project = os.environ.get("DESCOPE_PROJECT_ID", "").strip()
    machine = os.environ.get("NETWORK_ANALYSIS_MACHINE_TOKEN", "").strip()
    if not project or not machine:
        raise CatalogLookupError(
            "No catalog session. Set NETWORK_ANALYSIS_BEARER_TOKEN to a JWT, "
            "or NETWORK_ANALYSIS_MACHINE_TOKEN and DESCOPE_PROJECT_ID. "
            "Run under op run --env-file=prod.op."
        )
    request = Request(
        DESCOPE_EXCHANGE_URL,
        data=b'{"loginOptions":{}}',
        method="POST",
        headers={
            **_DESCOPE_HEADERS,
            "Authorization": f"Bearer {project}:{machine}",
            "x-descope-project-id": project,
        },
    )
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise CatalogLookupError(_http_message(exc, "Descope exchange")) from exc
    except (URLError, TimeoutError, json.JSONDecodeError, UnicodeError) as exc:
        raise CatalogLookupError(f"Descope exchange failed: {exc}") from exc
    token = body.get("sessionJwt") if isinstance(body, dict) else None
    if not isinstance(token, str) or not _is_jwt(token):
        raise CatalogLookupError("Descope exchange did not return a session JWT")
    return token


def _http_message(exc: HTTPError, what: str = "catalog") -> str:
    try:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
    except Exception:
        detail = ""
    suffix = f": {detail}" if detail else ""
    return f"{what} returned HTTP {exc.code}{suffix}"
