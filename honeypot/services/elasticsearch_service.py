"""Elasticsearch emulator (HTTP/JSON on 9200).

An unauthenticated Elasticsearch is scanned constantly, and for two quite
different reasons that are worth telling apart in the capture.

The first is **data theft**, and like an exposed Docker socket it needs no
exploit at all: ``GET /_cat/indices`` lists everything stored, and
``GET /_search`` returns it. Whole databases have been published from clusters
whose only misconfiguration was being reachable. The interesting record is
which indices the operator asked for — someone requesting ``users`` or
``customers`` by name knows what they are looking for.

The second is **ransom**. The Meow-style sweeps do not read anything: they
``DELETE`` every index and drop a note. A ``DELETE`` against ``/*`` or ``/_all``
is unambiguous and gets recorded as critical.

Older clusters also carried outright RCE — the Groovy and MVEL scripting holes
(CVE-2014-3120, CVE-2015-1427) reached through ``_search`` with a ``script``
field. Those payloads still arrive years later because the scanners were never
retired, and a body containing one is the highest-value capture this service
can make.

Nothing is stored, searched, deleted or executed. The service replies with a
plausible cluster so the client keeps going and reveals the rest of its
sequence — which index it wanted, which payload it carried.
"""

from __future__ import annotations

import asyncio
import json
import re

from honeypot.services.base import BaseService
from honeypot.session import HoneypotSession
from storage.models import EventType, Severity

MAX_HEADERS = 64
MAX_BODY_BYTES = 64 * 1024
MAX_REQUESTS = 50

CLUSTER_NAME = "elasticsearch"
CLUSTER_UUID = "0Yg7fH2xQ9SxKm3vB1nAqw"
NODE_NAME = "es-node-01"
VERSION = "6.8.23"  # old enough to be a plausible unpatched target

# Index names that suggest the operator knows what they are hunting for, rather
# than enumerating whatever happens to be there.
SENSITIVE_INDEX = re.compile(
    r"(user|customer|client|account|credential|password|payment|card|invoice|"
    r"employee|patient|order|email|token|secret|billing|kyc)",
    re.I,
)

# Scripting payloads from the Groovy/MVEL era. Still arriving years later.
SCRIPT_RCE = re.compile(
    r"(\"script\"|script_fields|java\.lang\.Runtime|getRuntime|"
    r"Math\.class\.forName|groovy|mvel|painless)",
    re.I,
)

# Notes left behind by ransom sweeps.
RANSOM_MARKER = re.compile(r"(meow|read_me|readme|recover|bitcoin|btc|ransom|restore)", re.I)


def classify_path(method: str, path: str) -> str:
    """Label one request by what it is trying to do."""
    bare = path.split("?", 1)[0].rstrip("/") or "/"
    upper = method.upper()

    if bare == "/":
        return "root-banner"
    if bare.startswith("/_cat"):
        return "cat-api"
    if bare in ("/_cluster/health", "/_cluster/state", "/_cluster/stats"):
        return "cluster-info"
    if bare in ("/_nodes", "/_nodes/stats") or bare.startswith("/_nodes/"):
        return "nodes-info"
    if bare.endswith("/_search") or bare == "/_search":
        return "search"
    if bare.endswith("/_bulk") or bare == "/_bulk":
        return "bulk"
    if upper == "DELETE":
        return "delete-index"
    if upper in ("PUT", "POST") and not bare.startswith("/_"):
        return "write-index"
    if upper == "GET" and not bare.startswith("/_"):
        return "read-index"
    return "other"


def index_from_path(path: str) -> str | None:
    """The index a request targets, if it names one."""
    bare = path.split("?", 1)[0].strip("/")
    if not bare:
        return None
    first = bare.split("/", 1)[0]
    if first.startswith("_"):
        return None
    return first[:128] or None


class ElasticsearchService(BaseService):
    name = "elasticsearch"

    async def handle_session(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        for _ in range(MAX_REQUESTS):
            request = await self._read_request(session, reader)
            if request is None:
                return
            method, path, headers, body = request

            route = classify_path(method, path)
            tags, severity = self._assess(method, path, route, body)

            recorded = session.record(
                EventType.HTTP_REQUEST,
                severity=severity,
                http_method=method,
                path=path,
                user_agent=headers.get("user-agent"),
                headers={k: v[:256] for k, v in list(headers.items())[:24]},
                status_code=200,
                payload_size=len(body),
                command=body.decode("utf-8", "replace")[:2048] if body else None,
                tags=tags,
                extra={"es_route": route, "index": index_from_path(path)},
            )
            if not recorded:
                return

            await self.send(writer, self._respond(method, path, route))

            if headers.get("connection", "").lower() == "close":
                return

    # ------------------------------------------------------------------ #

    async def _read_request(
        self, session: HoneypotSession, reader: asyncio.StreamReader
    ) -> tuple[str, str, dict[str, str], bytes] | None:
        """Read one HTTP request. None on EOF, timeout or an unusable request line."""
        line = await self.read_line(session, reader)
        if line is None:
            return None
        parts = line.split()
        if len(parts) < 2:
            return None
        method, path = parts[0][:16], parts[1][:2048]

        headers: dict[str, str] = {}
        for _ in range(MAX_HEADERS):
            header = await self.read_line(session, reader)
            if header is None or header == "":
                break
            name, _, value = header.partition(":")
            if name:
                headers[name.strip().lower()] = value.strip()

        # Content-Length is an attacker's claim, not a fact — cap before reading.
        body = b""
        try:
            declared = int(headers.get("content-length", "0"))
        except ValueError:
            declared = 0
        if declared > 0:
            body = await self.read_bytes(session, reader, min(declared, MAX_BODY_BYTES))

        return method, path, headers, body

    def _assess(
        self, method: str, path: str, route: str, body: bytes
    ) -> tuple[list[str], Severity]:
        """Tag and score one request.

        The ladder is about intent. Reading the banner is what every scanner on
        the internet does; deleting every index is the end of somebody's data.
        """
        tags = ["elasticsearch"]
        severity = Severity.LOW
        text = body.decode("utf-8", "replace") if body else ""
        index = index_from_path(path)

        if route in ("root-banner", "cluster-info", "nodes-info"):
            tags.append("es-recon")
            severity = Severity.LOW
        elif route == "cat-api":
            # Listing the indices is how a data-theft run starts.
            tags.append("es-enumerate-indices")
            severity = Severity.MEDIUM
        elif route in ("search", "read-index"):
            tags.append("es-data-access")
            severity = Severity.MEDIUM
        elif route in ("write-index", "bulk"):
            tags.append("es-write")
            severity = Severity.HIGH
        elif route == "delete-index":
            tags.append("es-delete")
            # DELETE /* or /_all is a wipe, not housekeeping.
            severity = Severity.CRITICAL if index in (None, "*", "_all") else Severity.HIGH
            if index in (None, "*", "_all"):
                tags.append("es-destroy-all")

        if index and SENSITIVE_INDEX.search(index):
            # Naming the index is the difference between enumerating and
            # knowing what you came for.
            tags.append("es-sensitive-index")
            severity = max(severity, Severity.HIGH, key=lambda s: s.rank)

        if text and SCRIPT_RCE.search(text):
            tags.append("es-script-rce")
            severity = Severity.CRITICAL

        if RANSOM_MARKER.search(path) or (text and RANSOM_MARKER.search(text)):
            tags.append("es-ransom-note")
            severity = Severity.CRITICAL

        return tags, severity

    # ------------------------------------------------------------------ #

    def _respond(self, method: str, path: str, route: str) -> bytes:
        payload = self._body_for(method, path, route)
        raw = json.dumps(payload, indent=2).encode()
        head = (
            "HTTP/1.1 200 OK\r\n"
            "content-type: application/json; charset=UTF-8\r\n"
            f"content-length: {len(raw)}\r\n"
            "\r\n"
        ).encode()
        return head + raw

    def _body_for(self, method: str, path: str, route: str) -> dict:
        index = index_from_path(path) or "logs-2026.08"

        if route == "root-banner":
            return {
                "name": NODE_NAME,
                "cluster_name": CLUSTER_NAME,
                "cluster_uuid": CLUSTER_UUID,
                "version": {
                    "number": VERSION,
                    "build_flavor": "default",
                    "build_type": "tar",
                    "build_hash": "4f67856",
                    "build_date": "2022-01-06T21:30:50.087716Z",
                    "build_snapshot": False,
                    "lucene_version": "7.7.3",
                    "minimum_wire_compatibility_version": "5.6.0",
                    "minimum_index_compatibility_version": "5.0.0",
                },
                "tagline": "You Know, for Search",
            }

        if route == "cluster-info":
            return {
                "cluster_name": CLUSTER_NAME,
                "status": "yellow",
                "timed_out": False,
                "number_of_nodes": 1,
                "number_of_data_nodes": 1,
                "active_primary_shards": 12,
                "active_shards": 12,
                "unassigned_shards": 12,
            }

        if route == "cat-api":
            # Plausible but empty-looking indices. Naming them keeps a
            # data-theft run progressing so we learn which one it wants.
            return [
                {"health": "yellow", "status": "open", "index": name, "docs.count": count}
                for name, count in (
                    ("logs-2026.08", "184203"),
                    ("metricbeat-6.8.23", "92310"),
                    ("app-events", "40118"),
                    (".kibana_1", "12"),
                )
            ]

        if route == "nodes-info":
            return {"cluster_name": CLUSTER_NAME, "nodes": {CLUSTER_UUID: {"name": NODE_NAME}}}

        if route == "search":
            # An empty result set: nothing real is ever served.
            return {
                "took": 3,
                "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                "hits": {"total": 0, "max_score": None, "hits": []},
            }

        if route == "delete-index":
            return {"acknowledged": True}

        if route in ("write-index", "bulk"):
            return {"took": 4, "errors": False, "_index": index, "result": "created"}

        return {"acknowledged": True, "_index": index}


__all__ = [
    "ElasticsearchService",
    "classify_path",
    "index_from_path",
    "SENSITIVE_INDEX",
    "SCRIPT_RCE",
]
